"""
Test validation error handling for Task 8.3

This test verifies that the StrategyValidator handles errors gracefully:
- Strategy mismatch → MISMATCH verdict
- Partial application → PARTIAL_SUCCESS verdict  
- Parameter extraction failure → use defaults

Feature: strategy-testing-production-parity
Task: 8.3 Implement validation error handling
Requirements: 2.5, 3.5
"""

import pytest
from unittest.mock import Mock, patch
from core.validation.strategy_validator import StrategyValidator
from core.test_result_models import PCAPAnalysisResult, ValidationResult


class TestValidationErrorHandling:
    """Test error handling in StrategyValidator"""
    
    def test_strategy_mismatch_handled_gracefully(self):
        """
        Test that strategy mismatch is detected and handled.
        
        Task 8.3: Handle strategy mismatch → MISMATCH verdict
        Requirements: 2.5
        """
        validator = StrategyValidator()
        
        # Declared strategy doesn't match what was applied
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="test.pcap",
            packet_count=10,
            detected_attacks=['split', 'fake'],
            parameters={'split_pos': 3},
            fake_packets_detected=1
        )
        
        result = validator.validate('split', pcap_analysis)
        
        # Should detect mismatch
        assert not result.strategy_match
        assert result.declared_strategy == 'split'
        assert result.applied_strategy == 'smart_combo_fake_split'
        assert any('mismatch' in w.lower() for w in result.warnings)
    
    def test_partial_application_handled_gracefully(self):
        """
        Test that partial strategy application is detected.
        
        Task 8.3: Handle partial application → PARTIAL_SUCCESS verdict
        Requirements: 2.5
        """
        validator = StrategyValidator()
        
        # Only one component of combo strategy was applied
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="test.pcap",
            packet_count=10,
            detected_attacks=['split'],  # Missing 'fake'
            parameters={'split_pos': 3},
            fake_packets_detected=0
        )
        
        result = validator.validate('smart_combo_split_fake', pcap_analysis)
        
        # Should detect incomplete application
        assert not result.all_attacks_applied
        assert result.missing_components == ['fake']
        assert any('Missing component' in e for e in result.errors)
    
    def test_parameter_extraction_failure_uses_defaults(self):
        """
        Test that parameter extraction failures fall back to defaults.
        
        Task 8.3: Handle parameter extraction failure → use defaults
        Requirements: 3.5
        """
        validator = StrategyValidator()
        
        # PCAP with no parameters extracted
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="test.pcap",
            packet_count=10,
            detected_attacks=['split'],
            parameters={},  # Empty parameters
            fake_packets_detected=0
        )
        
        result = validator.validate('split', pcap_analysis)
        
        # Should handle gracefully
        assert not result.parameters_extracted
        assert result.parameter_count == 0
        assert any('No parameters extracted' in w for w in result.warnings)
    
    def test_parameter_extraction_exception_handled(self):
        """
        Test that exceptions during parameter extraction are caught.
        
        Task 8.3: Handle parameter extraction failure → use defaults
        Requirements: 3.5
        """
        validator = StrategyValidator()
        
        # Create a mock PCAP analysis that raises exception on parameter access
        pcap_analysis = Mock(spec=PCAPAnalysisResult)
        pcap_analysis.packet_count = 10
        pcap_analysis.detected_attacks = ['split']
        pcap_analysis.fake_packets_detected = 0
        # Make parameters property raise exception
        type(pcap_analysis).parameters = property(lambda self: (_ for _ in ()).throw(ValueError("Test error")))
        
        # Should not raise exception
        result = validator.validate('split', pcap_analysis)
        
        # Should handle gracefully with defaults
        assert not result.parameters_extracted
        assert result.parameter_count == 0
    
    def test_unexpected_validation_error_returns_safe_result(self):
        """
        Test that unexpected errors during validation return a safe fallback result.
        
        Task 8.3: Comprehensive error handling
        Requirements: 2.5, 3.5
        """
        validator = StrategyValidator()
        
        # Create a mock that raises exception during decomposition
        with patch.object(validator, '_decompose_strategy', side_effect=RuntimeError("Unexpected error")):
            pcap_analysis = PCAPAnalysisResult(
                pcap_file="test.pcap",
                packet_count=10,
                detected_attacks=['split'],
                parameters={'split_pos': 3},
                fake_packets_detected=0
            )
            
            # Should not raise exception
            result = validator.validate('split', pcap_analysis)
            
            # Should return safe fallback
            assert not result.is_valid
            assert not result.all_attacks_applied
            assert not result.strategy_match
            assert result.applied_strategy == "unknown"
            assert any('Validation failed with error' in e for e in result.errors)
    
    def test_null_parameters_handled_correctly(self):
        """
        Test that null/None parameters are handled correctly.
        
        Task 8.3: Handle parameter extraction failure → use defaults
        Requirements: 3.5
        """
        validator = StrategyValidator()
        
        # PCAP with some null parameters
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="test.pcap",
            packet_count=10,
            detected_attacks=['split', 'fake'],
            parameters={'split_pos': 3, 'fake_ttl': None, 'split_count': None},
            fake_packets_detected=1
        )
        
        result = validator.validate('smart_combo_split_fake', pcap_analysis)
        
        # Should count only non-null parameters
        assert result.parameter_count == 1  # Only split_pos is non-null
        assert result.parameters_extracted  # At least one parameter exists


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
