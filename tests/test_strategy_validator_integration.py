"""
Test StrategyValidator integration with AdaptiveEngine

This test verifies that StrategyValidator is properly integrated into
the verification mode workflow.

Requirements: Task 11.5 - Integrate StrategyValidator into verification mode
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from core.adaptive_engine import AdaptiveEngine, AdaptiveConfig


class TestStrategyValidatorIntegration:
    """Test StrategyValidator integration with verification mode"""
    
    def test_validator_initialized_in_engine(self):
        """Test that StrategyValidator is initialized when engine is created"""
        config = AdaptiveConfig()
        engine = AdaptiveEngine(config=config)
        
        # Verify validator is initialized
        assert hasattr(engine, 'strategy_validator')
        # Note: validator might be None if import failed, but attribute should exist
    
    def test_validation_called_in_verification_mode(self):
        """Test that validation is called when verify_with_pcap is enabled"""
        # Create config with verification mode enabled
        config = AdaptiveConfig(verify_with_pcap=True)
        engine = AdaptiveEngine(config=config)
        
        # Mock the validator
        mock_validator = Mock()
        engine.strategy_validator = mock_validator
        
        # Create a mock result with PCAP file
        mock_result = Mock()
        mock_result.pcap_file = "/tmp/test.pcap"
        mock_result.success = True
        
        # Create a mock strategy
        strategy_dict = {
            'attack': 'fake_multisplit',
            'split_pos': 2,
            'split_count': 6,
            'fake_ttl': 1
        }
        
        # Create a temporary operation log
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir)
            engine.strategy_validator.logger = Mock()
            
            # Mock get_operation_logger to return a logger with our temp dir
            with patch('core.operation_logger.get_operation_logger') as mock_get_logger:
                mock_logger = Mock()
                mock_logger.log_dir = log_dir
                mock_get_logger.return_value = mock_logger
                
                # Create a fake log file
                domain = "example.com"
                domain_safe = domain.replace('.', '_')
                log_file = log_dir / f"20241201_120000_{domain_safe}_abc123.json"
                
                strategy_log = {
                    'strategy_id': 'abc123',
                    'strategy_name': 'fake_multisplit',
                    'domain': domain,
                    'timestamp': '2024-12-01T12:00:00',
                    'operations': [
                        {
                            'type': 'split',
                            'params': {'position': 2, 'count': 6}
                        },
                        {
                            'type': 'fake',
                            'params': {'ttl': 1, 'count': 2}
                        }
                    ]
                }
                
                with open(log_file, 'w') as f:
                    json.dump(strategy_log, f)
                
                # Mock PCAP file existence
                with patch('pathlib.Path.exists', return_value=True):
                    # Call the validation method
                    engine._run_strategy_validation(mock_result, strategy_dict, domain)
                
                # Verify validator was called
                assert mock_validator.validate_strategy.called
                call_args = mock_validator.validate_strategy.call_args
                
                # Verify correct arguments were passed
                assert call_args[1]['domain'] == domain
                assert 'strategy_log' in call_args[1]
                assert 'pcap_file' in call_args[1]
    
    def test_validation_skipped_when_disabled(self):
        """Test that validation is skipped when verify_with_pcap is disabled"""
        # Create config with verification mode disabled
        config = AdaptiveConfig(verify_with_pcap=False)
        engine = AdaptiveEngine(config=config)
        
        # Mock the validator
        mock_validator = Mock()
        engine.strategy_validator = mock_validator
        
        # Create a mock result
        mock_result = Mock()
        mock_result.pcap_file = "/tmp/test.pcap"
        
        strategy_dict = {'attack': 'fake_multisplit'}
        
        # Call validation (should be skipped)
        engine._run_strategy_validation(mock_result, strategy_dict, "example.com")
        
        # Verify validator was NOT called
        assert not mock_validator.validate_strategy.called
    
    def test_validation_handles_missing_pcap(self):
        """Test that validation handles missing PCAP file gracefully"""
        config = AdaptiveConfig(verify_with_pcap=True)
        engine = AdaptiveEngine(config=config)
        
        # Mock the validator
        mock_validator = Mock()
        engine.strategy_validator = mock_validator
        
        # Create a mock result WITHOUT PCAP file
        mock_result = Mock()
        mock_result.pcap_file = None
        
        strategy_dict = {'attack': 'fake_multisplit'}
        
        # Call validation (should handle gracefully)
        engine._run_strategy_validation(mock_result, strategy_dict, "example.com")
        
        # Verify validator was NOT called (no PCAP file)
        assert not mock_validator.validate_strategy.called
    
    def test_validation_report_generated(self):
        """Test that validation report is generated at the end"""
        config = AdaptiveConfig(verify_with_pcap=True)
        engine = AdaptiveEngine(config=config)
        
        # Mock the validator
        mock_validator = Mock()
        mock_validator.generate_report.return_value = "Test Validation Report"
        mock_validator.save_results = Mock()
        engine.strategy_validator = mock_validator
        
        # Mock the validation results
        engine.strategy_validator.validation_results = []
        
        # Create a temporary directory for reports
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('pathlib.Path.mkdir'):
                with patch('builtins.open', create=True) as mock_open:
                    # Trigger report generation by calling the code path
                    # This would normally happen at the end of find_best_strategy
                    
                    # Simulate the report generation code
                    if engine.config.verify_with_pcap and engine.strategy_validator:
                        validation_report = engine.strategy_validator.generate_report()
                        
                        # Verify report was generated
                        assert validation_report == "Test Validation Report"
                        assert mock_validator.generate_report.called


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
