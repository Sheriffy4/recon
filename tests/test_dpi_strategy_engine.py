"""
Unit tests for DPIStrategyEngine component.

Tests strategy orchestration, component integration, and error handling
with various packet scenarios and configurations.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import time
import struct

from core.bypass.strategies.dpi_strategy_engine import DPIStrategyEngine
from core.bypass.strategies.config_models import DPIConfig, SplitConfig, FoolingConfig
from core.bypass.strategies.exceptions import DPIStrategyError, ConfigurationError, PacketTooSmallError
from core.bypass.strategies.position_resolver import PositionResolver
from core.bypass.strategies.sni_detector import SNIDetector
from core.bypass.strategies.checksum_fooler import ChecksumFooler


class TestDPIStrategyEngine:
    """Test suite for DPIStrategyEngine component."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = DPIConfig(
            desync_mode="split",
            split_positions=[3, 10, "sni"],
            fooling_methods=["badsum"],
            enabled=True
        )
        self.engine = DPIStrategyEngine(self.config)
    
    def test_init(self):
        """Test DPIStrategyEngine initialization."""
        engine = DPIStrategyEngine(self.config)
        
        assert engine is not None
        assert engine.config == self.config
        assert hasattr(engine, '_position_resolver')
        assert hasattr(engine, '_packet_modifier')
        assert hasattr(engine, '_sni_detector')
        assert hasattr(engine, '_checksum_fooler')
        assert hasattr(engine, '_stats')
    
    def test_init_stats_initialization(self):
        """Test that statistics are properly initialized."""
        engine = DPIStrategyEngine(self.config)
        stats = engine.get_statistics()
        
        expected_keys = [
            'packets_processed', 'packets_split', 'badsum_applied',
            'sni_splits', 'numeric_splits', 'errors'
        ]
        
        for key in expected_keys:
            assert key in stats
            assert stats[key] == 0
    
    def test_component_setters(self):
        """Test component setter methods."""
        mock_resolver = Mock()
        mock_modifier = Mock()
        mock_detector = Mock()
        mock_fooler = Mock()
        
        self.engine.set_position_resolver(mock_resolver)
        self.engine.set_packet_modifier(mock_modifier)
        self.engine.set_sni_detector(mock_detector)
        self.engine.set_checksum_fooler(mock_fooler)
        
        assert self.engine._position_resolver == mock_resolver
        assert self.engine._packet_modifier == mock_modifier
        assert self.engine._sni_detector == mock_detector
        assert self.engine._checksum_fooler == mock_fooler
    
    def test_should_apply_enabled(self):
        """Test should_apply with enabled configuration."""
        packet = b'A' * 100
        
        result = self.engine.should_apply(packet)
        
        assert result is True
    
    def test_should_apply_disabled(self):
        """Test should_apply with disabled configuration."""
        config = DPIConfig(enabled=False, desync_mode="split", split_positions=[3], fooling_methods=[])
        engine = DPIStrategyEngine(config)
        packet = b'A' * 100
        
        result = engine.should_apply(packet)
        
        assert result is False
    
    def test_should_apply_wrong_mode(self):
        """Test should_apply with unsupported desync mode."""
        config = DPIConfig(enabled=True, desync_mode="disorder", split_positions=[3], fooling_methods=[])
        engine = DPIStrategyEngine(config)
        packet = b'A' * 100
        
        result = engine.should_apply(packet)
        
        assert result is False
    
    def test_should_split_packet_enabled(self):
        """Test should_split_packet with valid configuration."""
        packet = b'A' * 100
        
        result = self.engine.should_split_packet(packet)
        
        assert result is True
    
    def test_should_split_packet_disabled(self):
        """Test should_split_packet with disabled configuration."""
        config = DPIConfig(enabled=False, desync_mode="split", split_positions=[3], fooling_methods=[])
        engine = DPIStrategyEngine(config)
        packet = b'A' * 100
        
        result = engine.should_split_packet(packet)
        
        assert result is False
    
    def test_should_split_packet_no_positions(self):
        """Test should_split_packet with no split positions."""
        config = DPIConfig(enabled=True, desync_mode="split", split_positions=[], fooling_methods=[])
        engine = DPIStrategyEngine(config)
        packet = b'A' * 100
        
        result = engine.should_split_packet(packet)
        
        assert result is False
    
    def test_should_split_packet_too_small(self):
        """Test should_split_packet with packet too small."""
        packet = b'AB'  # 2 bytes - too small
        
        result = self.engine.should_split_packet(packet)
        
        assert result is False
    
    def test_should_split_packet_tls_client_hello(self):
        """Test should_split_packet with TLS Client Hello packet."""
        # Mock SNI detector to return True for is_client_hello
        with patch.object(self.engine._sni_detector, 'is_client_hello', return_value=True):
            packet = self._create_tls_client_hello()
            
            result = self.engine.should_split_packet(packet)
            
            assert result is True
    
    def test_get_split_positions_success(self):
        """Test get_split_positions with successful resolution."""
        packet = b'A' * 100
        expected_positions = [3, 10, 50]
        
        # Mock position resolver
        with patch.object(self.engine._position_resolver, 'resolve_positions', return_value=expected_positions):
            result = self.engine.get_split_positions(packet)
            
            assert result == expected_positions
    
    def test_get_split_positions_no_resolver(self):
        """Test get_split_positions with no position resolver."""
        self.engine._position_resolver = None
        packet = b'A' * 100
        
        result = self.engine.get_split_positions(packet)
        
        assert result == []
    
    def test_get_split_positions_error(self):
        """Test get_split_positions with resolver error."""
        packet = b'A' * 100
        
        # Mock position resolver to raise error
        with patch.object(self.engine._position_resolver, 'resolve_positions', side_effect=Exception("Test error")):
            result = self.engine.get_split_positions(packet)
            
            assert result == []
    
    def test_apply_priority_handling_sni_first(self):
        """Test priority handling with SNI having highest priority."""
        packet = self._create_tls_client_hello()
        positions = [3, 10, 80]  # 80 is SNI position
        
        # Mock SNI detector
        with patch.object(self.engine._sni_detector, 'is_client_hello', return_value=True):
            with patch.object(self.engine._sni_detector, 'find_sni_position', return_value=80):
                result = self.engine._apply_priority_handling(packet, positions)
                
                assert result[0] == 80  # SNI should be first
                assert 3 in result
                assert 10 in result
    
    def test_apply_priority_handling_numeric_only(self):
        """Test priority handling with numeric positions only."""
        packet = b'A' * 100
        positions = [10, 3, 50]  # Unsorted
        
        result = self.engine._apply_priority_handling(packet, positions)
        
        assert result == [3, 10, 50]  # Should be sorted
    
    def test_resolve_position_conflicts_limit(self):
        """Test position conflict resolution with too many positions."""
        packet = b'A' * 100
        positions = [3, 5, 7, 10, 15, 20, 25, 30]  # 8 positions, should be limited
        
        result = self.engine._resolve_position_conflicts(packet, positions)
        
        assert len(result) <= 3  # Should be limited to max 3
    
    def test_resolve_position_conflicts_small_fragments(self):
        """Test position conflict resolution filtering small fragments."""
        packet = b'A' * 20
        positions = [1, 2, 18, 19]  # Would create very small fragments
        
        result = self.engine._resolve_position_conflicts(packet, positions)
        
        # Should filter out positions that create fragments smaller than 3 bytes
        assert len(result) < len(positions)
    
    def test_apply_strategy_success(self):
        """Test successful strategy application."""
        packet = b'A' * 100
        expected_parts = [b'A' * 50, b'A' * 50]
        
        # Mock all components
        with patch.object(self.engine, 'should_split_packet', return_value=True):
            with patch.object(self.engine, 'get_split_positions', return_value=[50]):
                with patch.object(self.engine._packet_modifier, 'split_packet', return_value=expected_parts):
                    with patch.object(self.engine, '_apply_fooling_strategies', return_value=expected_parts):
                        result = self.engine.apply_strategy(packet)
                        
                        assert result == expected_parts
                        
                        # Check stats
                        stats = self.engine.get_statistics()
                        assert stats['packets_processed'] == 1
                        assert stats['packets_split'] == 1
    
    def test_apply_strategy_no_split_needed(self):
        """Test strategy application when no split is needed."""
        packet = b'A' * 100
        
        with patch.object(self.engine, 'should_split_packet', return_value=False):
            result = self.engine.apply_strategy(packet)
            
            assert result == [packet]  # Should return original packet
    
    def test_apply_strategy_no_valid_positions(self):
        """Test strategy application when no valid positions found."""
        packet = b'A' * 100
        
        with patch.object(self.engine, 'should_split_packet', return_value=True):
            with patch.object(self.engine, 'get_split_positions', return_value=[]):
                result = self.engine.apply_strategy(packet)
                
                assert result == [packet]  # Should return original packet
    
    def test_apply_strategy_split_failure(self):
        """Test strategy application with split failure."""
        packet = b'A' * 100
        
        with patch.object(self.engine, 'should_split_packet', return_value=True):
            with patch.object(self.engine, 'get_split_positions', return_value=[50]):
                with patch.object(self.engine._packet_modifier, 'split_packet', side_effect=Exception("Split error")):
                    result = self.engine.apply_strategy(packet)
                    
                    assert result == [packet]  # Should fallback to original
                    
                    # Check error stats
                    stats = self.engine.get_statistics()
                    assert stats['errors'] == 1
    
    def test_apply_strategy_component_validation_failure(self):
        """Test strategy application with component validation failure."""
        packet = b'A' * 100
        
        # Remove a required component
        self.engine._position_resolver = None
        
        result = self.engine.apply_strategy(packet)
        
        assert result == [packet]  # Should fallback to original
        
        # Check error stats
        stats = self.engine.get_statistics()
        assert stats['errors'] == 1
    
    def test_validate_components_success(self):
        """Test component validation with all components present."""
        # Should not raise any exception
        self.engine._validate_components()
    
    def test_validate_components_missing_resolver(self):
        """Test component validation with missing position resolver."""
        self.engine._position_resolver = None
        
        with pytest.raises(ConfigurationError):
            self.engine._validate_components()
    
    def test_validate_components_missing_modifier(self):
        """Test component validation with missing packet modifier."""
        self.engine._packet_modifier = None
        
        with pytest.raises(ConfigurationError):
            self.engine._validate_components()
    
    def test_apply_fooling_strategies_success(self):
        """Test applying fooling strategies successfully."""
        packets = [b'packet1', b'packet2', b'packet3']
        
        # Mock checksum fooler
        mock_fooler = Mock()
        mock_fooler.should_apply_badsum.side_effect = [True, False, False]  # Only first packet
        mock_fooler.apply_badsum.return_value = (b'modified_packet1', Mock())
        self.engine._checksum_fooler = mock_fooler
        
        result = self.engine._apply_fooling_strategies(packets)
        
        assert result[0] == b'modified_packet1'  # First packet modified
        assert result[1] == b'packet2'  # Second packet unchanged
        assert result[2] == b'packet3'  # Third packet unchanged
    
    def test_apply_fooling_strategies_no_fooler(self):
        """Test applying fooling strategies with no checksum fooler."""
        packets = [b'packet1', b'packet2']
        self.engine._checksum_fooler = None
        
        result = self.engine._apply_fooling_strategies(packets)
        
        assert result == packets  # Should return unchanged
    
    def test_apply_fooling_strategies_error(self):
        """Test applying fooling strategies with error."""
        packets = [b'packet1', b'packet2']
        
        # Mock checksum fooler to raise error
        mock_fooler = Mock()
        mock_fooler.should_apply_badsum.return_value = True
        mock_fooler.apply_badsum.side_effect = Exception("Fooling error")
        self.engine._checksum_fooler = mock_fooler
        
        result = self.engine._apply_fooling_strategies(packets)
        
        # Should return original packets on error
        assert result == packets
    
    def test_create_basic_tcp_info(self):
        """Test creating basic TCP info for badsum decisions."""
        packet = b'A' * 100
        
        tcp_info = self.engine._create_basic_tcp_info(packet)
        
        assert tcp_info.dst_port == 443  # Should assume HTTPS
        assert tcp_info.flags == 0x18  # PSH+ACK
        assert len(tcp_info.payload) > 0
    
    def test_get_sni_position_from_splits_found(self):
        """Test getting SNI position from split positions when found."""
        packet = self._create_tls_client_hello()
        split_positions = [3, 10, 80]
        
        # Mock SNI detector
        with patch.object(self.engine._sni_detector, 'find_sni_position', return_value=80):
            result = self.engine._get_sni_position_from_splits(packet, split_positions)
            
            assert result == 80
    
    def test_get_sni_position_from_splits_not_found(self):
        """Test getting SNI position from split positions when not found."""
        packet = self._create_tls_client_hello()
        split_positions = [3, 10, 50]
        
        # Mock SNI detector to return different position
        with patch.object(self.engine._sni_detector, 'find_sni_position', return_value=80):
            result = self.engine._get_sni_position_from_splits(packet, split_positions)
            
            assert result is None  # 80 not in split_positions
    
    def test_get_sni_position_from_splits_no_sni_config(self):
        """Test getting SNI position when SNI not configured."""
        config = DPIConfig(
            desync_mode="split",
            split_positions=[3, 10],  # No SNI
            fooling_methods=[],
            enabled=True
        )
        engine = DPIStrategyEngine(config)
        packet = self._create_tls_client_hello()
        split_positions = [3, 10]
        
        result = engine._get_sni_position_from_splits(packet, split_positions)
        
        assert result is None
    
    def test_create_split_config(self):
        """Test creating SplitConfig from main DPI config."""
        split_config = self.engine._create_split_config()
        
        assert isinstance(split_config, SplitConfig)
        assert split_config.numeric_positions == [3, 10]
        assert split_config.use_sni is True
        assert 'sni' in split_config.priority_order
    
    def test_create_fooling_config(self):
        """Test creating FoolingConfig from main DPI config."""
        fooling_config = self.engine._create_fooling_config()
        
        assert isinstance(fooling_config, FoolingConfig)
        assert fooling_config.badsum is True
    
    def test_get_statistics(self):
        """Test getting strategy engine statistics."""
        stats = self.engine.get_statistics()
        
        expected_keys = [
            'packets_processed', 'packets_split', 'badsum_applied',
            'sni_splits', 'numeric_splits', 'errors', 'split_rate', 'error_rate'
        ]
        
        for key in expected_keys:
            assert key in stats
    
    def test_reset_statistics(self):
        """Test resetting statistics."""
        # Generate some stats
        self.engine._stats['packets_processed'] = 10
        self.engine._stats['errors'] = 2
        
        self.engine.reset_statistics()
        
        stats = self.engine.get_statistics()
        assert stats['packets_processed'] == 0
        assert stats['errors'] == 0
    
    def test_handle_strategy_failure(self):
        """Test strategy failure handling."""
        packet = b'A' * 100
        error = Exception("Test error")
        context = "test_context"
        
        result = self.engine.handle_strategy_failure(packet, error, context)
        
        assert result == [packet]  # Should return original packet
        
        # Check error stats
        stats = self.engine.get_statistics()
        assert stats['errors'] == 1
    
    def test_is_critical_error_true(self):
        """Test critical error detection for critical errors."""
        critical_errors = [
            ConfigurationError("test", None, "test"),
            AttributeError("test"),
            ImportError("test")
        ]
        
        for error in critical_errors:
            assert self.engine._is_critical_error(error) is True
    
    def test_is_critical_error_false(self):
        """Test critical error detection for non-critical errors."""
        non_critical_errors = [
            ValueError("test"),
            RuntimeError("test"),
            Exception("test")
        ]
        
        for error in non_critical_errors:
            assert self.engine._is_critical_error(error) is False
    
    def test_create_fallback_mechanisms(self):
        """Test creating fallback mechanisms."""
        fallback = self.engine.create_fallback_mechanisms()
        
        assert isinstance(fallback, dict)
        assert 'disable_sni_on_parse_error' in fallback
        assert 'fallback_positions' in fallback
        assert 'max_consecutive_errors' in fallback
    
    def test_log_strategy_application(self):
        """Test logging strategy application details."""
        packet = b'A' * 100
        result = [b'A' * 50, b'A' * 50]
        split_positions = [50]
        processing_time = 10.5
        
        # Should not raise any exception
        self.engine.log_strategy_application(packet, result, split_positions, processing_time)
    
    def test_log_strategy_failure(self):
        """Test logging strategy failure details."""
        packet = b'A' * 100
        error = Exception("Test error")
        context = "test_context"
        
        # Should not raise any exception
        self.engine.log_strategy_failure(packet, error, context)
    
    def test_validate_strategy_result_valid(self):
        """Test strategy result validation with valid result."""
        original_packet = b'A' * 100
        result_packets = [b'A' * 50, b'A' * 50]
        
        result = self.engine.validate_strategy_result(original_packet, result_packets)
        
        assert result is True
    
    def test_validate_strategy_result_empty(self):
        """Test strategy result validation with empty result."""
        original_packet = b'A' * 100
        result_packets = []
        
        result = self.engine.validate_strategy_result(original_packet, result_packets)
        
        assert result is False
    
    def test_validate_strategy_result_size_mismatch(self):
        """Test strategy result validation with size mismatch."""
        original_packet = b'A' * 100
        result_packets = [b'A' * 30, b'A' * 30]  # Total 60, not 100
        
        result = self.engine.validate_strategy_result(original_packet, result_packets)
        
        assert result is False
    
    def test_get_error_recovery_suggestions(self):
        """Test getting error recovery suggestions."""
        error = ConfigurationError("test", None, "test")
        
        suggestions = self.engine.get_error_recovery_suggestions(error)
        
        assert isinstance(suggestions, list)
    
    def test_get_strategy_name(self):
        """Test getting strategy name."""
        name = self.engine.get_strategy_name()
        
        assert name == "DPI_SPLIT_STRATEGY"
    
    def test_sni_split_statistics_tracking(self):
        """Test that SNI splits are properly tracked in statistics."""
        packet = self._create_tls_client_hello()
        
        with patch.object(self.engine, 'should_split_packet', return_value=True):
            with patch.object(self.engine, 'get_split_positions', return_value=[80]):
                with patch.object(self.engine._packet_modifier, 'split_packet', return_value=[b'part1', b'part2']):
                    with patch.object(self.engine, '_get_sni_position_from_splits', return_value=80):
                        with patch.object(self.engine, '_apply_fooling_strategies', return_value=[b'part1', b'part2']):
                            self.engine.apply_strategy(packet)
                            
                            stats = self.engine.get_statistics()
                            assert stats['sni_splits'] == 1
                            assert stats['numeric_splits'] == 0
    
    def test_numeric_split_statistics_tracking(self):
        """Test that numeric splits are properly tracked in statistics."""
        packet = b'A' * 100
        
        with patch.object(self.engine, 'should_split_packet', return_value=True):
            with patch.object(self.engine, 'get_split_positions', return_value=[50]):
                with patch.object(self.engine._packet_modifier, 'split_packet', return_value=[b'part1', b'part2']):
                    with patch.object(self.engine, '_get_sni_position_from_splits', return_value=None):
                        with patch.object(self.engine, '_apply_fooling_strategies', return_value=[b'part1', b'part2']):
                            self.engine.apply_strategy(packet)
                            
                            stats = self.engine.get_statistics()
                            assert stats['numeric_splits'] == 1
                            assert stats['sni_splits'] == 0
    
    def _create_tls_client_hello(self) -> bytes:
        """Create a basic TLS Client Hello packet for testing."""
        # TLS record header
        packet = b'\x16\x03\x03\x01\x00'  # Content type, version, length
        
        # Handshake header
        packet += b'\x01\x00\x00\xFC'  # Handshake type, length
        
        # Client Hello
        packet += b'\x03\x03'  # Version
        packet += b'\x00' * 32  # Random
        packet += b'\x00'  # Session ID length
        packet += b'\x00\x02\x00\x35'  # Cipher suites
        packet += b'\x01\x00'  # Compression methods
        packet += b'\x00\x10'  # Extensions length
        
        # SNI extension
        packet += b'\x00\x00'  # Extension type (SNI)
        packet += b'\x00\x0C'  # Extension length
        packet += b'\x00\x0A'  # Server name list length
        packet += b'\x00'  # Name type
        packet += b'\x00\x07'  # Name length
        packet += b'test.com'  # Server name
        
        return packet


@pytest.fixture
def dpi_config():
    """Fixture providing a DPI configuration."""
    return DPIConfig(
        desync_mode="split",
        split_positions=[3, 10, "sni"],
        fooling_methods=["badsum"],
        enabled=True
    )


@pytest.fixture
def dpi_engine(dpi_config):
    """Fixture providing a DPI strategy engine."""
    return DPIStrategyEngine(dpi_config)


@pytest.fixture
def sample_packet():
    """Fixture providing a sample packet for testing."""
    return b'A' * 100


class TestDPIStrategyEngineIntegration:
    """Integration tests for DPIStrategyEngine with real components."""
    
    def test_full_integration_numeric_split(self, dpi_engine):
        """Test full integration with numeric split positions."""
        packet = b'A' * 100
        
        # This should work with real components
        result = dpi_engine.apply_strategy(packet)
        
        # Should either split the packet or return original
        assert isinstance(result, list)
        assert len(result) >= 1
        
        # If split occurred, total size should match
        if len(result) > 1:
            total_size = sum(len(part) for part in result)
            assert total_size == len(packet)
    
    def test_full_integration_tls_packet(self, dpi_engine):
        """Test full integration with TLS Client Hello packet."""
        packet = self._create_realistic_tls_client_hello()
        
        result = dpi_engine.apply_strategy(packet)
        
        assert isinstance(result, list)
        assert len(result) >= 1
        
        # Check statistics
        stats = dpi_engine.get_statistics()
        assert stats['packets_processed'] == 1
    
    def test_performance_benchmark(self, dpi_engine):
        """Test performance with multiple packets."""
        packets = [b'A' * (100 + i) for i in range(50)]  # 50 packets of varying sizes
        
        start_time = time.time()
        
        results = []
        for packet in packets:
            result = dpi_engine.apply_strategy(packet)
            results.append(result)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should process 50 packets in reasonable time (< 1 second)
        assert processing_time < 1.0
        assert len(results) == 50
        
        # Check final statistics
        stats = dpi_engine.get_statistics()
        assert stats['packets_processed'] == 50
    
    def test_error_resilience(self, dpi_engine):
        """Test error resilience with various problematic packets."""
        problematic_packets = [
            b'',  # Empty
            b'A',  # Too small
            b'A' * 10,  # Small
            b'\x00' * 100,  # All zeros
            b'\xFF' * 100,  # All ones
            self._create_malformed_tls_packet(),  # Malformed TLS
        ]
        
        for packet in problematic_packets:
            try:
                result = dpi_engine.apply_strategy(packet)
                # Should always return a list with at least the original packet
                assert isinstance(result, list)
                assert len(result) >= 1
            except Exception as e:
                pytest.fail(f"Engine should handle packet gracefully, but raised: {e}")
    
    def test_configuration_changes(self):
        """Test engine behavior with different configurations."""
        test_configs = [
            # Numeric only
            DPIConfig(desync_mode="split", split_positions=[3, 10], fooling_methods=[], enabled=True),
            # SNI only
            DPIConfig(desync_mode="split", split_positions=["sni"], fooling_methods=[], enabled=True),
            # With badsum
            DPIConfig(desync_mode="split", split_positions=[3], fooling_methods=["badsum"], enabled=True),
            # Disabled
            DPIConfig(desync_mode="split", split_positions=[3], fooling_methods=[], enabled=False),
        ]
        
        packet = self._create_realistic_tls_client_hello()
        
        for config in test_configs:
            engine = DPIStrategyEngine(config)
            result = engine.apply_strategy(packet)
            
            assert isinstance(result, list)
            assert len(result) >= 1
            
            if not config.enabled:
                # Disabled engine should return original packet
                assert result == [packet]
    
    def _create_realistic_tls_client_hello(self) -> bytes:
        """Create a realistic TLS Client Hello packet."""
        # TLS Record Header
        record = bytearray()
        record.extend(b'\x16')  # Content Type: Handshake
        record.extend(b'\x03\x03')  # Version: TLS 1.2
        
        # Handshake Message
        handshake = bytearray()
        handshake.extend(b'\x01')  # Handshake Type: Client Hello
        
        # Client Hello
        client_hello = bytearray()
        client_hello.extend(b'\x03\x03')  # Version: TLS 1.2
        client_hello.extend(b'\x12\x34\x56\x78' * 8)  # Random (32 bytes)
        client_hello.extend(b'\x00')  # Session ID Length
        
        # Cipher Suites
        cipher_suites = b'\x00\x35\x00\x2f\x00\x05'  # Multiple cipher suites
        client_hello.extend(struct.pack('!H', len(cipher_suites)))
        client_hello.extend(cipher_suites)
        
        # Compression Methods
        client_hello.extend(b'\x01\x00')  # null compression
        
        # Extensions
        extensions = bytearray()
        
        # SNI Extension
        sni_ext = bytearray()
        sni_ext.extend(b'\x00\x00')  # Extension Type: SNI
        
        sni_data = bytearray()
        hostname = b'www.example.com'
        sni_data.extend(struct.pack('!H', len(hostname) + 3))  # Server Name List Length
        sni_data.extend(b'\x00')  # Server Name Type: host_name
        sni_data.extend(struct.pack('!H', len(hostname)))  # Server Name Length
        sni_data.extend(hostname)  # Server Name
        
        sni_ext.extend(struct.pack('!H', len(sni_data)))
        sni_ext.extend(sni_data)
        
        extensions.extend(sni_ext)
        
        # Supported Groups Extension
        supported_groups_ext = bytearray()
        supported_groups_ext.extend(b'\x00\x0a')  # Extension Type
        groups_data = b'\x00\x04\x00\x17\x00\x18'  # secp256r1, secp384r1
        supported_groups_ext.extend(struct.pack('!H', len(groups_data)))
        supported_groups_ext.extend(groups_data)
        
        extensions.extend(supported_groups_ext)
        
        # Add extensions to Client Hello
        client_hello.extend(struct.pack('!H', len(extensions)))
        client_hello.extend(extensions)
        
        # Add Client Hello to handshake
        handshake.extend(struct.pack('!I', len(client_hello))[1:])  # Length (3 bytes)
        handshake.extend(client_hello)
        
        # Add handshake to record
        record.extend(struct.pack('!H', len(handshake)))
        record.extend(handshake)
        
        return bytes(record)
    
    def _create_malformed_tls_packet(self) -> bytes:
        """Create a malformed TLS packet for error testing."""
        packet = b'\x16\x03\x03\x00\x50'  # TLS record header
        packet += b'\x01\x00\x00\x4C'  # Handshake header
        packet += b'\xFF' * 76  # Malformed data
        return packet