"""
Integration test for Task 7.4: Route saves through coordinator

This test verifies that strategy saves are routed through the TestResultCoordinator
and StrategySaver, ensuring:
- Coordinator approval is checked before saving
- StrategySaver is used for atomic, deduplicated saves
- Non-SUCCESS verdicts block saves
- All three files are updated atomically

Feature: strategy-testing-production-parity
Requirements: 1.4, 1.5, 5.1, 5.2, 5.3, 5.4, 5.5, 9.4
"""

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
import asyncio

from core.test_result_coordinator import TestResultCoordinator
from core.test_result_models import TestVerdict, PCAPAnalysisResult
from core.validation.strategy_saver import StrategySaver
from core.adaptive_engine import AdaptiveEngine, AdaptiveConfig


class TestSaveRoutingThroughCoordinator:
    """
    Test that saves are routed through coordinator and use StrategySaver.
    
    Requirements: 1.4, 1.5, 5.1, 5.2, 5.3, 5.4, 5.5, 9.4
    """
    
    @pytest.fixture
    def temp_files(self):
        """Create temporary files for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            yield {
                'adaptive_knowledge': tmpdir_path / 'adaptive_knowledge.json',
                'domain_rules': tmpdir_path / 'domain_rules.json',
                'domain_strategies': tmpdir_path / 'domain_strategies.json',
                'pcap': tmpdir_path / 'test.pcap'
            }
    
    @pytest.fixture
    def coordinator(self):
        """Create TestResultCoordinator with mocked dependencies."""
        pcap_analyzer = Mock()
        pcap_analyzer.analyze_pcap.return_value = PCAPAnalysisResult(
            pcap_file='test.pcap',
            packet_count=10,
            detected_attacks=['split', 'fake'],
            parameters={'split_pos': 3, 'ttl': 64},
            split_positions=[3],
            fake_packets_detected=1,
            sni_values=['example.com'],
            analysis_time=0.1,
            analyzer_version='1.0'
        )
        
        strategy_validator = Mock()
        strategy_validator.validate.return_value = Mock(
            is_valid=True,
            all_attacks_applied=True,
            strategy_match=True
        )
        
        return TestResultCoordinator(
            pcap_analyzer=pcap_analyzer,
            strategy_validator=strategy_validator
        )
    
    @pytest.fixture
    def strategy_saver(self, temp_files):
        """Create StrategySaver with temporary files."""
        return StrategySaver(
            adaptive_knowledge_path=str(temp_files['adaptive_knowledge']),
            domain_rules_path=str(temp_files['domain_rules']),
            domain_strategies_path=str(temp_files['domain_strategies'])
        )
    
    @pytest.fixture
    def mock_strategy(self):
        """Create a mock strategy object."""
        strategy = Mock()
        strategy.name = 'smart_combo_split_fake'
        strategy.parameters = {'split_pos': 3, 'ttl': 64}
        strategy.attack_combination = ['split', 'fake']
        return strategy
    
    def test_success_verdict_allows_save(self, coordinator, strategy_saver, temp_files, mock_strategy):
        """
        Test that SUCCESS verdict allows strategy to be saved.
        
        Requirements: 1.4, 9.4
        """
        # Start test session
        session_id = coordinator.start_test(
            domain='example.com',
            strategy_name='smart_combo_split_fake',
            pcap_file=str(temp_files['pcap'])
        )
        
        # Record successful test
        coordinator.record_retransmission(session_id, 0)
        coordinator.record_response(session_id, response_status=200)
        
        # Create mock PCAP file
        temp_files['pcap'].touch()
        
        # Finalize test - should be SUCCESS
        verdict = coordinator.finalize_test(session_id)
        assert verdict == TestVerdict.SUCCESS
        
        # Check that save is approved
        should_save = coordinator.should_save_strategy(session_id)
        assert should_save is True
        
        # Perform save through StrategySaver
        save_result = strategy_saver.save_strategy(
            domain='example.com',
            strategy_name='smart_combo_split_fake',
            parameters={'split_pos': 3, 'ttl': 64},
            verdict=verdict,
            attacks=['split', 'fake']
        )
        
        # Verify save succeeded
        assert save_result.success is True
        assert save_result.was_duplicate is False
        assert len(save_result.files_updated) == 3
        
        # Verify all three files were created
        assert temp_files['adaptive_knowledge'].exists()
        assert temp_files['domain_rules'].exists()
        assert temp_files['domain_strategies'].exists()
    
    def test_fail_verdict_blocks_save(self, coordinator, strategy_saver, temp_files, mock_strategy):
        """
        Test that FAIL verdict blocks strategy from being saved.
        
        Requirements: 1.4, 1.5, 9.4
        """
        # Start test session
        session_id = coordinator.start_test(
            domain='example.com',
            strategy_name='smart_combo_split_fake',
            pcap_file=str(temp_files['pcap'])
        )
        
        # Record failed test (high retransmissions)
        coordinator.record_retransmission(session_id, 5)
        coordinator.record_response(session_id, timeout=True)
        
        # Create mock PCAP file
        temp_files['pcap'].touch()
        
        # Finalize test - should be FAIL
        verdict = coordinator.finalize_test(session_id)
        assert verdict == TestVerdict.FAIL
        
        # Check that save is blocked
        should_save = coordinator.should_save_strategy(session_id)
        assert should_save is False
        
        # Attempt save through StrategySaver - should be blocked
        save_result = strategy_saver.save_strategy(
            domain='example.com',
            strategy_name='smart_combo_split_fake',
            parameters={'split_pos': 3, 'ttl': 64},
            verdict=verdict,
            attacks=['split', 'fake']
        )
        
        # Verify save was blocked
        assert save_result.success is False
        assert 'Cannot save non-SUCCESS verdict' in save_result.error
        
        # Verify no files were created
        assert not temp_files['adaptive_knowledge'].exists()
        assert not temp_files['domain_rules'].exists()
        assert not temp_files['domain_strategies'].exists()
    
    def test_deduplication_prevents_multiple_saves(self, coordinator, strategy_saver, temp_files, mock_strategy):
        """
        Test that multiple save attempts are deduplicated.
        
        Requirements: 5.4, 5.5
        """
        # Start test session
        session_id = coordinator.start_test(
            domain='example.com',
            strategy_name='smart_combo_split_fake',
            pcap_file=str(temp_files['pcap'])
        )
        
        # Record successful test
        coordinator.record_retransmission(session_id, 0)
        coordinator.record_response(session_id, response_status=200)
        
        # Create mock PCAP file
        temp_files['pcap'].touch()
        
        # Finalize test
        verdict = coordinator.finalize_test(session_id)
        assert verdict == TestVerdict.SUCCESS
        
        # First save
        save_result_1 = strategy_saver.save_strategy(
            domain='example.com',
            strategy_name='smart_combo_split_fake',
            parameters={'split_pos': 3, 'ttl': 64},
            verdict=verdict,
            attacks=['split', 'fake']
        )
        
        assert save_result_1.success is True
        assert save_result_1.was_duplicate is False
        
        # Second save attempt - should be deduplicated
        save_result_2 = strategy_saver.save_strategy(
            domain='example.com',
            strategy_name='smart_combo_split_fake',
            parameters={'split_pos': 3, 'ttl': 64},
            verdict=verdict,
            attacks=['split', 'fake']
        )
        
        assert save_result_2.success is True
        assert save_result_2.was_duplicate is True
        assert len(save_result_2.files_updated) == 0
    
    @pytest.mark.asyncio
    async def test_adaptive_engine_uses_coordinator_for_saves(self, temp_files):
        """
        Test that AdaptiveEngine routes saves through coordinator.
        
        This is an integration test that verifies the full flow:
        1. AdaptiveEngine initializes coordinator and saver
        2. Test completes with SUCCESS verdict
        3. Save is routed through coordinator.should_save_strategy()
        4. Save is performed via StrategySaver
        
        Requirements: 9.4
        """
        # Create config with coordinator enabled
        config = AdaptiveConfig(
            use_test_result_coordinator=True,
            max_trials=1
        )
        
        # Mock the bypass engine and other dependencies
        with patch('core.adaptive_engine.UnifiedBypassEngine'), \
             patch('core.adaptive_engine.StrategyFailureAnalyzer'), \
             patch('core.adaptive_engine.DPIFingerprintService'), \
             patch('core.adaptive_engine.StrategyIntentEngine'), \
             patch('core.adaptive_engine.StrategyGenerator'), \
             patch('core.dns.doh_integration.DoHIntegration'):
            
            # Create engine
            engine = AdaptiveEngine(config=config)
            
            # Verify coordinator and saver are initialized
            assert engine.test_result_coordinator is not None
            assert engine.strategy_saver is not None
            
            # Mock the PCAP analyzer to return valid results
            mock_pcap_result = PCAPAnalysisResult(
                pcap_file=str(temp_files['pcap']),
                packet_count=10,
                detected_attacks=['split', 'fake'],
                parameters={'split_pos': 3, 'ttl': 64},
                split_positions=[3],
                fake_packets_detected=1,
                sni_values=['example.com'],
                analysis_time=0.1,
                analyzer_version='1.0'
            )
            engine.test_result_coordinator.pcap_analyzer.analyze_pcap = Mock(return_value=mock_pcap_result)
            
            # Mock the validator to return valid result
            mock_validation_result = Mock(
                is_valid=True,
                all_attacks_applied=True,
                strategy_match=True,
                declared_strategy='smart_combo_split_fake',
                applied_strategy='smart_combo_split_fake'
            )
            engine.test_result_coordinator.strategy_validator.validate = Mock(return_value=mock_validation_result)
            
            # Mock strategy object
            mock_strategy = Mock()
            mock_strategy.name = 'smart_combo_split_fake'
            mock_strategy.parameters = {'split_pos': 3, 'ttl': 64}
            mock_strategy.attack_combination = ['split', 'fake']
            
            # Start a test session
            session_id = engine.test_result_coordinator.start_test(
                domain='example.com',
                strategy_name='smart_combo_split_fake',
                pcap_file=str(temp_files['pcap'])
            )
            
            # Record successful test
            engine.test_result_coordinator.record_retransmission(session_id, 0)
            engine.test_result_coordinator.record_response(session_id, response_status=200)
            
            # Create mock PCAP file
            temp_files['pcap'].touch()
            
            # Finalize test
            verdict = engine.test_result_coordinator.finalize_test(session_id)
            assert verdict == TestVerdict.SUCCESS
            
            # Mock the StrategySaver to track calls
            original_saver = engine.strategy_saver
            engine.strategy_saver = Mock(wraps=original_saver)
            
            # Call _save_working_strategy
            await engine._save_working_strategy(
                domain='example.com',
                strategy=mock_strategy,
                pcap_file=str(temp_files['pcap']),
                session_id=session_id
            )
            
            # Verify StrategySaver.save_strategy was called
            engine.strategy_saver.save_strategy.assert_called_once()
            
            # Verify the call arguments
            call_args = engine.strategy_saver.save_strategy.call_args
            assert call_args.kwargs['domain'] == 'example.com'
            assert call_args.kwargs['strategy_name'] == 'smart_combo_split_fake'
            assert call_args.kwargs['verdict'] == TestVerdict.SUCCESS
    
    def test_mismatch_verdict_blocks_save(self, coordinator, strategy_saver, temp_files):
        """
        Test that MISMATCH verdict blocks strategy from being saved.
        
        Requirements: 1.4, 1.5, 9.4
        """
        # Start test session
        session_id = coordinator.start_test(
            domain='example.com',
            strategy_name='smart_combo_split_fake',
            pcap_file=str(temp_files['pcap'])
        )
        
        # Record test with no retransmissions
        coordinator.record_retransmission(session_id, 0)
        coordinator.record_response(session_id, response_status=200)
        
        # Create mock PCAP file
        temp_files['pcap'].touch()
        
        # Mock validator to return mismatch
        coordinator.strategy_validator.validate.return_value = Mock(
            is_valid=False,
            all_attacks_applied=True,
            strategy_match=False,
            declared_strategy='smart_combo_split_fake',
            applied_strategy='split'
        )
        
        # Finalize test - should be MISMATCH
        verdict = coordinator.finalize_test(session_id)
        assert verdict == TestVerdict.MISMATCH
        
        # Check that save is blocked
        should_save = coordinator.should_save_strategy(session_id)
        assert should_save is False
        
        # Attempt save - should be blocked
        save_result = strategy_saver.save_strategy(
            domain='example.com',
            strategy_name='smart_combo_split_fake',
            parameters={'split_pos': 3},
            verdict=verdict,
            attacks=['split', 'fake']
        )
        
        # Verify save was blocked
        assert save_result.success is False
        assert 'Cannot save non-SUCCESS verdict' in save_result.error


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
