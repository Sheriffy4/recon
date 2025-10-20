"""
Integration tests for full attack flow.

Tests the complete end-to-end execution of attacks through the entire system:
AttackRegistry -> AttackDispatcher -> BypassTechniques -> Attack execution
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List

from core.bypass.attacks.attack_registry import get_attack_registry
from core.bypass.engine.attack_dispatcher import create_attack_dispatcher
from core.bypass.techniques.primitives import BypassTechniques
from core.bypass.attacks.metadata import AttackCategories


class TestFullAttackFlow:
    """Test suite for complete attack execution flow."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.registry = get_attack_registry()
        self.techniques = Mock(spec=BypassTechniques)
        self.dispatcher = create_attack_dispatcher(self.techniques)
        
        # Mock all technique methods to return valid results (list of tuples)
        mock_result = [(b"segment1", 0, {"is_fake": False}), (b"segment2", 10, {"is_fake": True})]
        self.techniques.apply_fakeddisorder.return_value = mock_result
        self.techniques.apply_seqovl.return_value = mock_result
        self.techniques.apply_multidisorder.return_value = mock_result
        self.techniques.apply_disorder.return_value = mock_result
        self.techniques.apply_multisplit.return_value = mock_result
        self.techniques.apply_fake_packet_race.return_value = mock_result
        self.techniques.apply_wssize_limit.return_value = mock_result
        self.techniques.apply_tlsrec_split.return_value = mock_result
    
    def test_fakeddisorder_full_flow(self):
        """Test complete fakeddisorder attack flow."""
        # Test data
        attack_type = "fakeddisorder"
        payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"
        params = {
            "split_pos": 5,
            "ttl": 3,
            "fooling": ["badsum"]
        }
        
        # Step 1: Validate parameters through registry
        validation_result = self.registry.validate_parameters(attack_type, params)
        assert validation_result.is_valid, f"Parameter validation failed: {validation_result.error_message}"
        
        # Step 2: Get handler from registry
        handler = self.registry.get_attack_handler(attack_type)
        assert handler is not None, "Handler not found in registry"
        
        # Step 3: Dispatch attack through dispatcher
        result = self.dispatcher.dispatch_attack(attack_type, params, payload, {})
        
        # Step 4: Verify execution
        assert result is not None, "Dispatcher returned None"
        # Check that apply_fakeddisorder was called with correct parameters
        self.techniques.apply_fakeddisorder.assert_called_once()
        call_args = self.techniques.apply_fakeddisorder.call_args
        assert call_args[0][0] == payload  # First arg is payload
        assert call_args[1]["split_pos"] == 5  # split_pos parameter
        assert call_args[1]["fake_ttl"] == 3  # fake_ttl parameter
        assert call_args[1]["fooling_methods"] == ["badsum"]  # fooling_methods parameter
    
    def test_seqovl_full_flow(self):
        """Test complete seqovl attack flow."""
        attack_type = "seqovl"
        payload = b"TLS handshake data"
        params = {
            "split_pos": 10,
            "overlap_size": 20,
            "fake_ttl": 2
        }
        
        # Full flow validation
        validation_result = self.registry.validate_parameters(attack_type, params)
        assert validation_result.is_valid
        
        handler = self.registry.get_attack_handler(attack_type)
        assert handler is not None
        
        result = self.dispatcher.dispatch_attack(attack_type, params, payload, {})
        
        assert result is not None
        # Check that apply_seqovl was called with correct parameters
        self.techniques.apply_seqovl.assert_called_once()
        call_args = self.techniques.apply_seqovl.call_args
        assert call_args[0][0] == payload  # First arg is payload
        assert call_args[0][1] == 10  # split_pos parameter
        assert call_args[0][2] == 20  # overlap_size parameter
        assert call_args[0][3] == 2  # fake_ttl parameter
        assert call_args[0][4] == ['badsum']  # fooling_methods parameter (default)
    
    def test_multidisorder_full_flow(self):
        """Test complete multidisorder attack flow."""
        attack_type = "multidisorder"
        payload = b"HTTP request data"
        params = {
            "positions": [1, 5, 10]
        }
        
        validation_result = self.registry.validate_parameters(attack_type, params)
        assert validation_result.is_valid
        
        handler = self.registry.get_attack_handler(attack_type)
        assert handler is not None
        
        result = self.dispatcher.dispatch_attack(attack_type, params, payload, {})
        
        assert result is not None
        self.techniques.apply_multidisorder.assert_called_once()
        
        # Verify positions were passed correctly
        call_args = self.techniques.apply_multidisorder.call_args
        assert call_args[0][0] == payload  # First arg is payload
        assert call_args[0][1] == [1, 5, 10]  # Second arg is positions
    
    def test_disorder_full_flow(self):
        """Test complete disorder attack flow."""
        attack_type = "disorder"
        payload = b"Test payload"
        params = {"split_pos": 7}
        
        validation_result = self.registry.validate_parameters(attack_type, params)
        assert validation_result.is_valid
        
        handler = self.registry.get_attack_handler(attack_type)
        assert handler is not None
        
        result = self.dispatcher.dispatch_attack(attack_type, params, payload, {})
        
        assert result is not None
        self.techniques.apply_disorder.assert_called_once()
        call_args = self.techniques.apply_disorder.call_args
        assert call_args[0][0] == payload  # First arg is payload
        assert call_args[1]["split_pos"] == 7  # split_pos parameter
        # Note: ack_first may not be explicitly passed if it's using the default value

    def test_disorder2_full_flow(self):
        """Test complete disorder2 attack flow (ack_first=True)."""
        attack_type = "disorder2"
        payload = b"Test payload"
        params = {"split_pos": 7}
        
        validation_result = self.registry.validate_parameters(attack_type, params)
        assert validation_result.is_valid
        
        handler = self.registry.get_attack_handler(attack_type)
        assert handler is not None
        
        result = self.dispatcher.dispatch_attack(attack_type, params, payload, {})
        
        assert result is not None
        self.techniques.apply_disorder.assert_called_once()
        call_args = self.techniques.apply_disorder.call_args
        assert call_args[0][0] == payload  # First arg is payload
        assert call_args[0][1] == 7  # split_pos parameter (positional)
        # The ack_first parameter is passed as a keyword argument in the actual implementation
    
    def test_multisplit_full_flow(self):
        """Test complete multisplit attack flow."""
        attack_type = "multisplit"
        payload = b"Large payload for splitting"
        params = {"positions": [3, 8, 15]}
        
        validation_result = self.registry.validate_parameters(attack_type, params)
        assert validation_result.is_valid
        
        handler = self.registry.get_attack_handler(attack_type)
        assert handler is not None
        
        result = self.dispatcher.dispatch_attack(attack_type, params, payload, {})
        
        assert result is not None
        self.techniques.apply_multisplit.assert_called_once()
        call_args = self.techniques.apply_multisplit.call_args
        assert call_args[0][0] == payload  # First arg is payload
        assert call_args[1]["positions"] == [3, 8, 15]  # positions parameter
    
    def test_split_to_multisplit_conversion_flow(self):
        """Test that split attack converts to multisplit correctly."""
        attack_type = "split"
        payload = b"Split test payload"
        params = {"split_pos": 5}
        
        validation_result = self.registry.validate_parameters(attack_type, params)
        assert validation_result.is_valid
        
        handler = self.registry.get_attack_handler(attack_type)
        assert handler is not None
        
        result = self.dispatcher.dispatch_attack(attack_type, params, payload, {})
        
        assert result is not None
        # split should convert to multisplit with single position
        self.techniques.apply_multisplit.assert_called_once()
        call_args = self.techniques.apply_multisplit.call_args
        assert call_args[0][0] == payload  # First arg is payload
        assert call_args[1]["positions"] == [5]  # positions parameter
    
    def test_fake_packet_race_full_flow(self):
        """Test complete fake packet race attack flow."""
        attack_type = "fake"
        payload = b"Race condition test"
        params = {
            "fooling": ["badseq", "badack"],
            "ttl": 3
        }
        
        validation_result = self.registry.validate_parameters(attack_type, params)
        assert validation_result.is_valid
        
        handler = self.registry.get_attack_handler(attack_type)
        assert handler is not None
        
        result = self.dispatcher.dispatch_attack(attack_type, params, payload, {})
        
        assert result is not None
        self.techniques.apply_fake_packet_race.assert_called_once()
        call_args = self.techniques.apply_fake_packet_race.call_args
        assert call_args[0][0] == payload  # First arg is payload
        assert call_args[0][1] == 3  # ttl parameter
        assert call_args[0][2] == ["badseq", "badack"]  # fooling parameter
    
    def test_alias_resolution_full_flow(self):
        """Test that attack aliases work through the full flow."""
        # Test using alias instead of canonical name
        attack_type = "fake_disorder"  # Alias for fakeddisorder
        payload = b"Alias test payload"
        params = {"split_pos": 3}
        
        validation_result = self.registry.validate_parameters(attack_type, params)
        assert validation_result.is_valid
        
        handler = self.registry.get_attack_handler(attack_type)
        assert handler is not None
        
        result = self.dispatcher.dispatch_attack(attack_type, params, payload, {})
        
        assert result is not None
        # Should resolve to fakeddisorder handler
        self.techniques.apply_fakeddisorder.assert_called_once()
    
    def test_special_split_pos_resolution_flow(self):
        """Test special split_pos values work through full flow."""
        attack_type = "fakeddisorder"
        payload = b"TLS handshake with SNI"
        params = {
            "split_pos": "sni",  # Special value
            "ttl": 4
        }
        
        validation_result = self.registry.validate_parameters(attack_type, params)
        assert validation_result.is_valid
        
        # Mock the dispatcher's SNI finding
        with patch.object(self.dispatcher, '_find_sni_position', return_value=15):
            result = self.dispatcher.dispatch_attack(attack_type, params, payload, {})
        
        assert result is not None
        # Should resolve sni to actual position
        self.techniques.apply_fakeddisorder.assert_called_once()
        call_args = self.techniques.apply_fakeddisorder.call_args
        assert call_args[1]["split_pos"] == 15  # split_pos should be resolved to 15
    
    def test_parameter_validation_failure_flow(self):
        """Test that invalid parameters are caught in the flow."""
        attack_type = "fakeddisorder"
        payload = b"Test payload"
        params = {
            "split_pos": -1,  # Invalid value
            "ttl": 300  # Invalid value
        }
        
        # Should fail at validation step
        validation_result = self.registry.validate_parameters(attack_type, params)
        assert validation_result.is_valid is False
        # The error message might be about ttl or split_pos depending on which is checked first
        error_message = validation_result.error_message
        assert error_message is not None
        assert "must be" in error_message or "Invalid" in error_message
    
    def test_unknown_attack_type_flow(self):
        """Test handling of unknown attack types."""
        attack_type = "nonexistent_attack"
        payload = b"Test payload"
        params = {}
        
        # Should fail at registry lookup
        handler = self.registry.get_attack_handler(attack_type)
        assert handler is None
        
        # Dispatcher should raise an exception for unknown attack types
        with pytest.raises(ValueError):
            self.dispatcher.dispatch_attack(attack_type, params, payload, {})


class TestAttackFlowWithRealTechniques:
    """Test attack flow with real BypassTechniques (mocked at lower level)."""
    
    def setup_method(self):
        """Set up test fixtures with real techniques object."""
        self.registry = get_attack_registry()
        
        # Create real BypassTechniques but mock its dependencies
        with patch('core.bypass.techniques.primitives.struct'):
            self.techniques = BypassTechniques()
        
        self.dispatcher = create_attack_dispatcher(self.techniques)
    
    def test_fakeddisorder_with_real_techniques(self):
        """Test fakeddisorder with real BypassTechniques object."""
        attack_type = "fakeddisorder"
        payload = b"HTTP/1.1 request"
        params = {"split_pos": 5, "ttl": 3}
        
        # Execute through full flow
        result = self.dispatcher.dispatch_attack(attack_type, params, payload, {})
        
        # Verify the flow completed (result should be a list of segments)
        assert result is not None
        assert isinstance(result, list)
    
    def test_all_attack_types_execute_without_errors(self):
        """Test that all registered attack types can execute without errors."""
        payload = b"Test payload for all attacks"
        
        # Get all registered attack types
        attack_types = self.registry.list_attacks()
        
        for attack_type in attack_types:
            try:
                # Use minimal valid parameters for each attack type
                if attack_type in ["fakeddisorder", "fake_disorder"]:
                    params = {"split_pos": 3, "ttl": 3}
                elif attack_type in ["seqovl"]:
                    params = {"split_pos": 3, "overlap_size": 10, "ttl": 3}
                elif attack_type in ["multisplit", "multidisorder"]:
                    params = {"positions": [1, 5]}
                elif attack_type in ["fake"]:
                    params = {"ttl": 3}
                else:
                    # Default parameters for other attack types
                    params = {"split_pos": 3}
                
                result = self.dispatcher.dispatch_attack(
                    attack_type, params, payload, {}
                )
                
                # Should not raise exception
                assert True, f"Attack {attack_type} executed successfully"
                
            except Exception as e:
                pytest.fail(f"Attack {attack_type} failed with error: {e}")

class TestAttackFlowPerformance:
    """Basic performance tests for attack flow."""
    
    def setup_method(self):
        """Set up performance test fixtures."""
        self.registry = get_attack_registry()
        self.techniques = Mock(spec=BypassTechniques)
        self.dispatcher = create_attack_dispatcher(self.techniques)
        
        # Mock all methods to return quickly with valid results
        mock_result = [(b"segment", 0, {"is_fake": False})]
        for method_name in ['apply_fakeddisorder', 'apply_seqovl', 'apply_multidisorder', 
                           'apply_disorder', 'apply_multisplit', 'apply_fake_packet_race',
                           'apply_wssize_limit', 'apply_tlsrec_split']:
            getattr(self.techniques, method_name).return_value = mock_result
    
    def test_attack_dispatch_performance(self):
        """Test that attack dispatch is reasonably fast."""
        import time
        
        attack_type = "fakeddisorder"
        payload = b"Performance test payload"
        params = {"split_pos": 5, "ttl": 3}
        
        # Warm up
        for _ in range(10):
            self.dispatcher.dispatch_attack(attack_type, params, payload, {})
        
        # Measure performance
        start_time = time.time()
        iterations = 1000
        
        for _ in range(iterations):
            result = self.dispatcher.dispatch_attack(attack_type, params, payload, {})
        
        end_time = time.time()
        total_time = end_time - start_time
        avg_time_per_dispatch = total_time / iterations
        
        # Should be very fast (less than 1ms per dispatch)
        assert avg_time_per_dispatch < 0.001, f"Dispatch too slow: {avg_time_per_dispatch:.6f}s per call"
        
        print(f"Performance: {avg_time_per_dispatch*1100:.3f}ms per dispatch")
    
    def test_registry_lookup_performance(self):
        """Test that registry lookups are fast."""
        import time
        
        attack_types = ["fakeddisorder", "seqovl", "multidisorder", "disorder", "split"]
        
        # Warm up
        for _ in range(100):
            for attack_type in attack_types:
                self.registry.get_attack_handler(attack_type)
        
        # Measure performance
        start_time = time.time()
        iterations = 10000
        
        for _ in range(iterations):
            for attack_type in attack_types:
                handler = self.registry.get_attack_handler(attack_type)
        
        end_time = time.time()
        total_time = end_time - start_time
        avg_time_per_lookup = total_time / (iterations * len(attack_types))
        
        # Should be very fast (less than 0.1ms per lookup)
        assert avg_time_per_lookup < 0.0001, f"Registry lookup too slow: {avg_time_per_lookup:.6f}s per call"
        
        print(f"Registry performance: {avg_time_per_lookup*1000:.3f}ms per lookup")