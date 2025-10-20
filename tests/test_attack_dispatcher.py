"""
Unit tests for AttackDispatcher component.

Tests attack dispatching, parameter resolution, special parameter handling,
and error conditions for the DPI bypass attack dispatcher system.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List, Tuple

from core.bypass.engine.attack_dispatcher import AttackDispatcher, create_attack_dispatcher
from core.bypass.attacks.attack_registry import AttackRegistry
from core.bypass.attacks.metadata import AttackMetadata, AttackCategories, ValidationResult, SpecialParameterValues
from core.bypass.techniques.primitives import BypassTechniques


class TestAttackDispatcher:
    """Test suite for AttackDispatcher component."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Create mock techniques
        self.mock_techniques = Mock(spec=BypassTechniques)
        
        # Create mock registry
        self.mock_registry = Mock(spec=AttackRegistry)
        
        # Create dispatcher
        self.dispatcher = AttackDispatcher(self.mock_techniques, self.mock_registry)
        
        # Common test data
        self.test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        self.test_packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '93.184.216.34',
            'src_port': 12345,
            'dst_port': 80
        }
    
    def test_init_with_registry(self):
        """Test AttackDispatcher initialization with provided registry."""
        dispatcher = AttackDispatcher(self.mock_techniques, self.mock_registry)
        
        assert dispatcher.techniques == self.mock_techniques
        assert dispatcher.registry == self.mock_registry
    
    def test_init_without_registry(self):
        """Test AttackDispatcher initialization without registry (uses global)."""
        with patch('core.bypass.engine.attack_dispatcher.get_attack_registry') as mock_get_registry:
            mock_global_registry = Mock()
            mock_get_registry.return_value = mock_global_registry
            
            dispatcher = AttackDispatcher(self.mock_techniques)
            
            assert dispatcher.techniques == self.mock_techniques
            assert dispatcher.registry == mock_global_registry
            mock_get_registry.assert_called_once()
    
    def test_dispatch_attack_success_fakeddisorder(self):
        """Test successful dispatch of fakeddisorder attack."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)
        
        mock_handler = Mock()
        expected_recipe = [
            (b"fake_data", 0, {"is_fake": True, "ttl": 3}),
            (b"GET ", 0, {"is_fake": False, "tcp_flags": 0x18}),
            (b"/ HTTP/1.1\r\nHost: example.com\r\n\r\n", 4, {"is_fake": False, "tcp_flags": 0x18})
        ]
        mock_handler.return_value = expected_recipe
        self.mock_registry.get_attack_handler.return_value = mock_handler
        
        # Test parameters
        params = {"split_pos": 4, "ttl": 3}
        
        # Execute
        result = self.dispatcher.dispatch_attack("fakeddisorder", params, self.test_payload, self.test_packet_info)
        
        # Verify
        assert result == expected_recipe
        self.mock_registry._resolve_attack_type.assert_called_once_with("fakeddisorder")
        self.mock_registry.validate_parameters.assert_called_once_with("fakeddisorder", params)
        self.mock_registry.get_attack_handler.assert_called_once_with("fakeddisorder")
        mock_handler.assert_called_once()
    
    def test_dispatch_attack_success_seqovl(self):
        """Test successful dispatch of seqovl attack."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "seqovl"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)
        
        mock_handler = Mock()
        expected_recipe = [
            (b"GET", 0, {"is_fake": True, "ttl": 3}),
            (self.test_payload, 0, {"is_fake": False, "tcp_flags": 0x18})
        ]
        mock_handler.return_value = expected_recipe
        self.mock_registry.get_attack_handler.return_value = mock_handler
        
        # Test parameters
        params = {"split_pos": 4, "overlap_size": 3, "ttl": 3}
        
        # Execute
        result = self.dispatcher.dispatch_attack("seqovl", params, self.test_payload, self.test_packet_info)
        
        # Verify
        assert result == expected_recipe
        self.mock_registry._resolve_attack_type.assert_called_once_with("seqovl")
        self.mock_registry.validate_parameters.assert_called_once_with("seqovl", params)
        mock_handler.assert_called_once()
    
    def test_dispatch_attack_validation_failure(self):
        """Test dispatch with parameter validation failure."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(
            False, "Missing required parameter 'split_pos'"
        )
        
        # Test parameters (missing split_pos)
        params = {"ttl": 3}
        
        # Execute and verify exception
        with pytest.raises(ValueError) as exc_info:
            self.dispatcher.dispatch_attack("fakeddisorder", params, self.test_payload, self.test_packet_info)
        
        assert "Invalid parameters for attack 'fakeddisorder'" in str(exc_info.value)
        assert "Missing required parameter 'split_pos'" in str(exc_info.value)
    
    def test_dispatch_attack_no_handler(self):
        """Test dispatch when no handler is found."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "unknown_attack"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)
        self.mock_registry.get_attack_handler.return_value = None
        
        # Execute and verify exception
        with pytest.raises(ValueError) as exc_info:
            self.dispatcher.dispatch_attack("unknown_attack", {}, self.test_payload, self.test_packet_info)
        
        assert "No handler found for attack type 'unknown_attack'" in str(exc_info.value)
    
    def test_dispatch_attack_handler_returns_invalid_recipe(self):
        """Test dispatch when handler returns invalid recipe."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)
        
        mock_handler = Mock()
        mock_handler.return_value = None  # Invalid recipe
        self.mock_registry.get_attack_handler.return_value = mock_handler
        
        # Execute and verify exception
        with pytest.raises(RuntimeError) as exc_info:
            self.dispatcher.dispatch_attack("fakeddisorder", {"split_pos": 3}, self.test_payload, self.test_packet_info)
        
        assert "returned invalid recipe" in str(exc_info.value)
    
    def test_dispatch_attack_handler_exception(self):
        """Test dispatch when handler raises exception."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)
        
        mock_handler = Mock()
        mock_handler.side_effect = Exception("Handler error")
        self.mock_registry.get_attack_handler.return_value = mock_handler
        
        # Execute and verify exception propagation
        with pytest.raises(Exception) as exc_info:
            self.dispatcher.dispatch_attack("fakeddisorder", {"split_pos": 3}, self.test_payload, self.test_packet_info)
        
        assert "Handler error" in str(exc_info.value)
    
    def test_normalize_attack_type(self):
        """Test attack type normalization."""
        # Setup mock
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        
        # Test normalization
        result = self.dispatcher._normalize_attack_type("  FakeDisorder  ")
        
        assert result == "fakeddisorder"
        self.mock_registry._resolve_attack_type.assert_called_once_with("fakedisorder")
    
    def test_resolve_parameters_basic(self):
        """Test basic parameter resolution without special values."""
        params = {"split_pos": 5, "ttl": 3, "fooling": ["badsum"]}
        
        result = self.dispatcher._resolve_parameters(params, self.test_payload, self.test_packet_info)
        
        # Should return same parameters since no special values
        assert result["split_pos"] == 5
        assert result["ttl"] == 3
        assert result["fooling"] == ["badsum"]
    
    def test_resolve_parameters_split_pos_int(self):
        """Test parameter resolution with integer split_pos."""
        params = {"split_pos": 10}
        
        result = self.dispatcher._resolve_parameters(params, self.test_payload, self.test_packet_info)
        
        # Should clamp to payload length
        expected_pos = min(10, len(self.test_payload) - 1)
        assert result["split_pos"] == expected_pos
    
    def test_resolve_parameters_split_pos_cipher(self):
        """Test parameter resolution with cipher special value."""
        params = {"split_pos": "cipher"}
        
        with patch.object(self.dispatcher, '_find_cipher_position', return_value=43) as mock_find:
            result = self.dispatcher._resolve_parameters(params, self.test_payload, self.test_packet_info)
            
            assert result["split_pos"] == 43
            mock_find.assert_called_once_with(self.test_payload)
    
    def test_resolve_parameters_split_pos_sni(self):
        """Test parameter resolution with SNI special value."""
        params = {"split_pos": "sni"}
        
        with patch.object(self.dispatcher, '_find_sni_position', return_value=25) as mock_find:
            result = self.dispatcher._resolve_parameters(params, self.test_payload, self.test_packet_info)
            
            assert result["split_pos"] == 25
            mock_find.assert_called_once_with(self.test_payload)
    
    def test_resolve_parameters_split_pos_midsld(self):
        """Test parameter resolution with midsld special value."""
        params = {"split_pos": "midsld"}
        
        with patch.object(self.dispatcher, '_find_midsld_position', return_value=15) as mock_find:
            result = self.dispatcher._resolve_parameters(params, self.test_payload, self.test_packet_info)
            
            assert result["split_pos"] == 15
            mock_find.assert_called_once_with(self.test_payload, self.test_packet_info)
    
    def test_resolve_parameters_positions_list(self):
        """Test parameter resolution with positions list."""
        params = {"positions": [3, "cipher", 10]}
        
        with patch.object(self.dispatcher, '_find_cipher_position', return_value=43):
            result = self.dispatcher._resolve_parameters(params, self.test_payload, self.test_packet_info)
            
            expected_positions = [3, 43, 10]
            assert result["positions"] == expected_positions
    
    def test_resolve_parameters_ttl_aliases(self):
        """Test parameter resolution with TTL aliases."""
        # Test fake_ttl -> ttl
        params1 = {"fake_ttl": 5}
        result1 = self.dispatcher._resolve_parameters(params1, self.test_payload, self.test_packet_info)
        assert result1["ttl"] == 5
        assert result1["fake_ttl"] == 5
        
        # Test ttl -> fake_ttl
        params2 = {"ttl": 7}
        result2 = self.dispatcher._resolve_parameters(params2, self.test_payload, self.test_packet_info)
        assert result2["ttl"] == 7
        assert result2["fake_ttl"] == 7
    
    def test_resolve_parameters_fooling_aliases(self):
        """Test parameter resolution with fooling aliases."""
        params = {"fooling": ["badsum", "badseq"]}
        
        result = self.dispatcher._resolve_parameters(params, self.test_payload, self.test_packet_info)
        
        assert result["fooling"] == ["badsum", "badseq"]
        assert result["fooling_methods"] == ["badsum", "badseq"]
    
    def test_resolve_split_position_invalid_string(self):
        """Test split position resolution with invalid string."""
        result = self.dispatcher._resolve_split_position("invalid", self.test_payload, self.test_packet_info)
        
        # Should return middle of payload as fallback
        expected = len(self.test_payload) // 2
        assert result == expected
    
    def test_resolve_split_position_string_number(self):
        """Test split position resolution with string number."""
        result = self.dispatcher._resolve_split_position("15", self.test_payload, self.test_packet_info)
        
        assert result == 15
    
    def test_resolve_split_position_unknown_type(self):
        """Test split position resolution with unknown type."""
        result = self.dispatcher._resolve_split_position([], self.test_payload, self.test_packet_info)
        
        # Should return middle of payload as fallback
        expected = len(self.test_payload) // 2
        assert result == expected
    
    def test_find_cipher_position_valid_tls(self):
        """Test finding cipher position in valid TLS ClientHello."""
        # Create mock TLS ClientHello packet with enough data
        tls_payload = (
            b'\x16'  # TLS Record Type (Handshake)
            b'\x03\x03'  # TLS Version
            b'\x00\x50'  # Length
            b'\x01'  # Handshake Type (ClientHello)
            b'\x00\x00\x4c'  # Handshake Length
            b'\x03\x03'  # Version
            + b'\x00' * 32  # Random (32 bytes)
            + b'\x00'  # Session ID Length (0 bytes)
            + b'\x00\x02'  # Cipher Suites Length (2 bytes)
            + b'\x00\x00'  # Some cipher suite data
        )
        
        result = self.dispatcher._find_cipher_position(tls_payload)
        
        # The actual implementation skips session ID and returns position after it
        # With session_id_len = 0, position should be 43 + 1 + 0 = 44
        # And pos + 2 (46) <= len(payload) (48) should be true
        assert result == 44
    
    def test_find_cipher_position_invalid_packet(self):
        """Test finding cipher position in invalid packet."""
        invalid_payload = b"Not a TLS packet"
        
        result = self.dispatcher._find_cipher_position(invalid_payload)
        
        # Should return middle as fallback
        expected = len(invalid_payload) // 2
        assert result == expected
    
    def test_find_sni_position_found(self):
        """Test finding SNI position when SNI extension exists."""
        # Mock payload with SNI extension - need to place it after position 40
        prefix = b'A' * 45  # Ensure we have enough data before SNI pattern
        payload_with_sni = prefix + b'\x00\x00' + b'some_data'
        
        result = self.dispatcher._find_sni_position(payload_with_sni)
        
        # Should find the SNI pattern at position 45
        assert result == 45
    
    def test_find_sni_position_not_found(self):
        """Test finding SNI position when SNI extension doesn't exist."""
        result = self.dispatcher._find_sni_position(self.test_payload)
        
        # Should return middle as fallback
        expected = len(self.test_payload) // 2
        assert result == expected
    
    def test_find_midsld_position_with_domain(self):
        """Test finding midsld position with extractable domain."""
        with patch.object(self.dispatcher, '_extract_domain_from_sni', return_value='example.com'):
            # Mock payload containing the domain
            domain_payload = b'some_data_example.com_more_data'
            
            result = self.dispatcher._find_midsld_position(domain_payload, self.test_packet_info)
            
            # Should find position in middle of 'example' (SLD)
            # example.com -> SLD is 'example', middle is at position 3-4
            assert isinstance(result, int)
            assert result > 0
    
    def test_find_midsld_position_no_domain(self):
        """Test finding midsld position when domain can't be extracted."""
        with patch.object(self.dispatcher, '_extract_domain_from_sni', return_value=None):
            result = self.dispatcher._find_midsld_position(self.test_payload, self.test_packet_info)
            
            # Should return middle as fallback
            expected = len(self.test_payload) // 2
            assert result == expected
    
    def test_extract_domain_from_sni_success(self):
        """Test successful domain extraction from SNI."""
        # The implementation: name_start = i + 9, reads length from name_start:name_start+2
        # and domain from name_start+2. So we need length bytes at position i+9
        sni_payload = (
            b'prefix_data'
            b'\x00\x00'  # SNI extension type (position 11, i=11)
            b'\x00\x00\x00\x00\x00\x00\x00'  # 7 bytes padding
            b'\x00\x0b'  # Name length (11) at position i+9 = 20
            b'example.com'  # Domain name at position i+11 = 22
            b'suffix_data'
        )
        
        result = self.dispatcher._extract_domain_from_sni(sni_payload)
        
        assert result == 'example.com'
    
    def test_extract_domain_from_sni_not_found(self):
        """Test domain extraction when SNI is not found."""
        result = self.dispatcher._extract_domain_from_sni(self.test_payload)
        
        assert result is None
    
    def test_extract_domain_from_sni_invalid_format(self):
        """Test domain extraction with invalid SNI format."""
        # Malformed SNI extension
        malformed_sni = b'\x00\x00\x00\x01\xff'  # Invalid lengths
        
        result = self.dispatcher._extract_domain_from_sni(malformed_sni)
        
        assert result is None
    
    def test_dispatch_attack_with_warnings(self):
        """Test dispatch with parameter validation warnings."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        
        validation_result = ValidationResult(True)
        validation_result.warnings = ["Parameter 'ttl' is high, consider lower value"]
        self.mock_registry.validate_parameters.return_value = validation_result
        
        mock_handler = Mock()
        mock_handler.return_value = [(b"test", 0, {"is_fake": False})]
        self.mock_registry.get_attack_handler.return_value = mock_handler
        
        # Execute with logging patch to capture warnings
        with patch('core.bypass.engine.attack_dispatcher.logger') as mock_logger:
            result = self.dispatcher.dispatch_attack(
                "fakeddisorder", 
                {"split_pos": 3, "ttl": 100}, 
                self.test_payload, 
                self.test_packet_info
            )
            
            # Verify warning was logged
            mock_logger.warning.assert_called_once()
            warning_call = mock_logger.warning.call_args[0][0]
            assert "parameter warning" in warning_call
    
    def test_get_current_time(self):
        """Test current time method."""
        with patch('time.time', return_value=1234567890.123):
            result = self.dispatcher._get_current_time()
            
            assert result == 1234567890.123


class TestAttackDispatcherIntegration:
    """Integration tests for AttackDispatcher with real components."""
    
    def setup_method(self):
        """Set up test fixtures with real components."""
        self.techniques = BypassTechniques()
        
        # Use real registry but patch external attack loading
        with patch('core.bypass.attacks.attack_registry.AttackRegistry._register_external_attacks'):
            from core.bypass.attacks.attack_registry import AttackRegistry
            self.registry = AttackRegistry()
        
        self.dispatcher = AttackDispatcher(self.techniques, self.registry)
        self.test_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        self.test_packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '93.184.216.34',
            'src_port': 12345,
            'dst_port': 80
        }
    
    def test_dispatch_fakeddisorder_integration(self):
        """Test full fakeddisorder dispatch with real components."""
        params = {"split_pos": 4, "ttl": 3, "fooling": ["badsum"]}
        
        result = self.dispatcher.dispatch_attack("fakeddisorder", params, self.test_payload, self.test_packet_info)
        
        # Verify result structure
        assert isinstance(result, list)
        assert len(result) >= 2  # Should have at least fake + real parts
        
        # Verify first segment is fake
        fake_segment = result[0]
        assert len(fake_segment) == 3
        assert isinstance(fake_segment[0], bytes)  # payload
        assert isinstance(fake_segment[1], int)    # offset
        assert isinstance(fake_segment[2], dict)   # options
        assert fake_segment[2].get("is_fake") is True
    
    def test_dispatch_seqovl_integration(self):
        """Test full seqovl dispatch with real components."""
        params = {"split_pos": 5, "overlap_size": 3, "fake_ttl": 3}
        
        result = self.dispatcher.dispatch_attack("seqovl", params, self.test_payload, self.test_packet_info)
        
        # Verify result structure
        assert isinstance(result, list)
        assert len(result) >= 2  # Should have fake overlap + real full
        
        # Check that we have both fake and real segments
        has_fake = any(seg[2].get("is_fake") is True for seg in result)
        has_real = any(seg[2].get("is_fake") is False for seg in result)
        assert has_fake and has_real
    
    def test_dispatch_disorder_integration(self):
        """Test full disorder dispatch with real components."""
        params = {"split_pos": 6}
        
        result = self.dispatcher.dispatch_attack("disorder", params, self.test_payload, self.test_packet_info)
        
        # Verify result structure
        assert isinstance(result, list)
        assert len(result) >= 2  # Should have reordered parts
        
        # All segments should be real (no fake packets in disorder)
        for segment in result:
            assert segment[2].get("is_fake") is False
    
    def test_dispatch_multisplit_integration(self):
        """Test full multisplit dispatch with real components."""
        params = {"positions": [3, 8, 15]}
        
        result = self.dispatcher.dispatch_attack("multisplit", params, self.test_payload, self.test_packet_info)
        
        # Verify result structure
        assert isinstance(result, list)
        assert len(result) >= 3  # Should have multiple splits
        
        # All segments should be real
        for segment in result:
            assert segment[2].get("is_fake") is False


class TestCreateAttackDispatcher:
    """Test suite for create_attack_dispatcher factory function."""
    
    def test_create_attack_dispatcher(self):
        """Test factory function creates dispatcher correctly."""
        mock_techniques = Mock(spec=BypassTechniques)
        
        with patch('core.bypass.engine.attack_dispatcher.get_attack_registry') as mock_get_registry:
            mock_registry = Mock()
            mock_get_registry.return_value = mock_registry
            
            dispatcher = create_attack_dispatcher(mock_techniques)
            
            assert isinstance(dispatcher, AttackDispatcher)
            assert dispatcher.techniques == mock_techniques
            assert dispatcher.registry == mock_registry


class TestAttackDispatcherEdgeCases:
    """Test suite for AttackDispatcher edge cases and error conditions."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.mock_techniques = Mock(spec=BypassTechniques)
        self.mock_registry = Mock(spec=AttackRegistry)
        self.dispatcher = AttackDispatcher(self.mock_techniques, self.mock_registry)
    
    def test_dispatch_empty_payload(self):
        """Test dispatch with empty payload."""
        # Setup mocks
        self.mock_registry._resolve_attack_type.return_value = "fakeddisorder"
        self.mock_registry.validate_parameters.return_value = ValidationResult(True)
        
        mock_handler = Mock()
        mock_handler.return_value = [(b"", 0, {"is_fake": False})]
        self.mock_registry.get_attack_handler.return_value = mock_handler
        
        # Execute with empty payload
        result = self.dispatcher.dispatch_attack("fakeddisorder", {"split_pos": 1}, b"", {})
        
        assert isinstance(result, list)
        assert len(result) >= 1
    
    def test_dispatch_very_large_split_pos(self):
        """Test dispatch with split_pos larger than payload."""
        payload = b"short"
        params = {"split_pos": 1000}  # Much larger than payload
        
        result = self.dispatcher._resolve_split_position(params["split_pos"], payload, {})
        
        # Should be clamped to payload length - 1
        expected = len(payload) - 1
        assert result == expected
    
    def test_dispatch_zero_split_pos(self):
        """Test dispatch with zero split_pos."""
        payload = b"test_payload"
        params = {"split_pos": 0}
        
        result = self.dispatcher._resolve_split_position(params["split_pos"], payload, {})
        
        # Should be clamped to minimum 1
        assert result == 1
    
    def test_find_cipher_position_short_payload(self):
        """Test cipher position finding with very short payload."""
        short_payload = b"short"
        
        result = self.dispatcher._find_cipher_position(short_payload)
        
        # Should return middle as fallback
        expected = len(short_payload) // 2
        assert result == expected
    
    def test_find_midsld_position_single_label_domain(self):
        """Test midsld position with single label domain (no SLD)."""
        with patch.object(self.dispatcher, '_extract_domain_from_sni', return_value='localhost'):
            result = self.dispatcher._find_midsld_position(b"test_payload", {})
            
            # Should return middle as fallback for single label
            expected = len(b"test_payload") // 2
            assert result == expected
    
    def test_resolve_parameters_positions_empty_list(self):
        """Test parameter resolution with empty positions list."""
        params = {"positions": []}
        
        result = self.dispatcher._resolve_parameters(params, b"test", {})
        
        assert result["positions"] == []
    
    def test_resolve_parameters_positions_mixed_types(self):
        """Test parameter resolution with mixed position types."""
        params = {"positions": [1, "5", "cipher"]}
        
        with patch.object(self.dispatcher, '_find_cipher_position', return_value=10):
            result = self.dispatcher._resolve_parameters(params, b"test_payload_long", {})
            
            expected_positions = [1, 5, 10]
            assert result["positions"] == expected_positions