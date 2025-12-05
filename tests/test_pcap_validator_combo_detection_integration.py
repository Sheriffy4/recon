"""
Integration tests for PCAP Validator Combo Detection.

This test suite validates the complete flow from PCAP analysis through
strategy validation, ensuring that combo strategies are correctly detected
and validated.

Feature: pcap-validator-combo-detection
Requirements: 1.1, 2.1, 3.2, 4.1, 4.2, 4.3, 5.4
"""

import pytest
import tempfile
from pathlib import Path
from typing import List
from unittest.mock import Mock

from core.pcap.analyzer import PCAPAnalyzer
from core.validation.strategy_validator import StrategyValidator
from core.test_result_models import PCAPAnalysisResult


class TestPCAPValidatorComboDetectionIntegration:
    """Integration tests for PCAP validator combo detection."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = PCAPAnalyzer()
        self.validator = StrategyValidator()
    
    def test_full_flow_with_combo_strategy_pcap(self):
        """
        Test 7.1: Test full flow with combo strategy PCAP
        
        Requirements: 1.1, 3.2, 4.1
        
        This test validates the complete flow:
        1. PCAPAnalyzer detects attacks in PCAP
        2. PCAPAnalyzer determines strategy_type from attacks
        3. StrategyValidator uses strategy_type for validation
        4. Validation succeeds with strategy_match = True
        
        Note: Using disorder + multisplit + badseq where badseq is a fooling attack
        that should be filtered out.
        """
        # Create a mock PCAP analysis result with combo strategy
        # Simulating: disorder + multisplit + badseq detected
        # badseq is a fooling attack and should be filtered
        detected_attacks = ['disorder', 'multisplit', 'badseq']
        
        # Step 1: Test PCAPAnalyzer._determine_strategy_type_from_attacks
        strategy_type, combo_attacks = self.analyzer._determine_strategy_type_from_attacks(
            detected_attacks
        )
        
        # Verify strategy_type is correct (badseq filtered out)
        assert strategy_type == "smart_combo_disorder_multisplit", \
            f"Expected 'smart_combo_disorder_multisplit', got '{strategy_type}'"
        
        # Verify combo_attacks filters out fooling attacks (badseq)
        assert combo_attacks == ['disorder', 'multisplit'], \
            f"Expected ['disorder', 'multisplit'], got {combo_attacks}"
        
        # Step 2: Create PCAPAnalysisResult with strategy_type
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="/tmp/test_combo.pcap",
            packet_count=10,
            detected_attacks=detected_attacks,
            strategy_type=strategy_type,
            combo_attacks=combo_attacks,
            parameters={'split_pos': 3},
            split_positions=[3],
            fake_packets_detected=0,
            sni_values=['example.com']
        )
        
        # Step 3: Run StrategyValidator.validate()
        # Declared strategy matches the detected strategy
        declared_strategy = "smart_combo_disorder_multisplit"
        validation_result = self.validator.validate(
            declared_strategy_name=declared_strategy,
            pcap_analysis=pcap_analysis
        )
        
        # Step 4: Verify strategy_match = True
        assert validation_result.strategy_match, \
            f"Expected strategy_match=True, got {validation_result.strategy_match}"
        
        assert validation_result.applied_strategy == strategy_type, \
            f"Expected applied_strategy='{strategy_type}', got '{validation_result.applied_strategy}'"
        
        assert validation_result.applied_strategy_source == "pcap_analyzer", \
            f"Expected source='pcap_analyzer', got '{validation_result.applied_strategy_source}'"
        
        print("✅ Test 7.1 passed: Full flow with combo strategy PCAP")
    
    def test_fallback_to_reconstruction(self):
        """
        Test 7.2: Test fallback to reconstruction
        
        Requirements: 4.2
        
        This test validates that when strategy_type is not available,
        the validator falls back to reconstructing from detected_attacks.
        """
        # Create PCAPAnalysisResult WITHOUT strategy_type
        detected_attacks = ['fake', 'split']
        
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="/tmp/test_fallback.pcap",
            packet_count=5,
            detected_attacks=detected_attacks,
            # strategy_type is None (not set)
            parameters={'split_pos': 2, 'fake_ttl': 1},
            split_positions=[2],
            fake_packets_detected=1,
            sni_values=['example.com']
        )
        
        # Run StrategyValidator.validate()
        declared_strategy = "smart_combo_fake_split"
        validation_result = self.validator.validate(
            declared_strategy_name=declared_strategy,
            pcap_analysis=pcap_analysis
        )
        
        # Verify it falls back to _determine_applied_strategy
        assert validation_result.applied_strategy_source == "reconstruction", \
            f"Expected source='reconstruction', got '{validation_result.applied_strategy_source}'"
        
        # Verify correct strategy name is determined
        assert validation_result.applied_strategy == "smart_combo_fake_split", \
            f"Expected 'smart_combo_fake_split', got '{validation_result.applied_strategy}'"
        
        # Verify strategy_match = True
        assert validation_result.strategy_match, \
            f"Expected strategy_match=True, got {validation_result.strategy_match}"
        
        print("✅ Test 7.2 passed: Fallback to reconstruction")
    
    def test_metadata_priority(self):
        """
        Test 7.3: Test metadata priority
        
        Requirements: 4.3
        
        This test validates that when both executed_attacks_from_log and
        strategy_type are available, executed_attacks_from_log is used
        (priority 1).
        """
        # Create PCAPAnalysisResult with BOTH executed_attacks_from_log and strategy_type
        detected_attacks = ['disorder', 'multisplit']
        
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="/tmp/test_metadata.pcap",
            packet_count=8,
            detected_attacks=detected_attacks,
            executed_attacks_from_log="smart_combo_disorder_multisplit",  # From metadata
            strategy_type="smart_combo_disorder_multisplit",  # From PCAPAnalyzer
            combo_attacks=['disorder', 'multisplit'],
            parameters={'split_pos': 3},
            split_positions=[3],
            fake_packets_detected=0,
            sni_values=['example.com']
        )
        
        # Run StrategyValidator.validate()
        declared_strategy = "smart_combo_disorder_multisplit"
        validation_result = self.validator.validate(
            declared_strategy_name=declared_strategy,
            pcap_analysis=pcap_analysis
        )
        
        # Verify executed_attacks_from_log is used (priority 1)
        assert validation_result.applied_strategy_source == "metadata", \
            f"Expected source='metadata', got '{validation_result.applied_strategy_source}'"
        
        assert validation_result.applied_strategy == "smart_combo_disorder_multisplit", \
            f"Expected 'smart_combo_disorder_multisplit', got '{validation_result.applied_strategy}'"
        
        # Verify strategy_match = True
        assert validation_result.strategy_match, \
            f"Expected strategy_match=True, got {validation_result.strategy_match}"
        
        print("✅ Test 7.3 passed: Metadata priority")
    
    def test_normalization_equivalence(self):
        """
        Test 7.4: Test normalization equivalence
        
        Requirements: 5.4
        
        This test validates that strategies differing only in multisplit/split
        are recognized as equivalent through normalization.
        """
        # Create PCAPAnalysisResult with multisplit
        detected_attacks = ['disorder', 'multisplit']
        
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="/tmp/test_normalization.pcap",
            packet_count=7,
            detected_attacks=detected_attacks,
            strategy_type="smart_combo_disorder_multisplit",
            combo_attacks=['disorder', 'multisplit'],
            parameters={'split_pos': 3},
            split_positions=[3, 5],
            fake_packets_detected=0,
            sni_values=['example.com']
        )
        
        # Declare strategy with "split" instead of "multisplit"
        declared_strategy = "smart_combo_disorder_split"
        
        # Run StrategyValidator.validate()
        validation_result = self.validator.validate(
            declared_strategy_name=declared_strategy,
            pcap_analysis=pcap_analysis
        )
        
        # Verify they are recognized as equivalent
        assert validation_result.strategy_match, \
            f"Expected strategy_match=True (multisplit=split equivalence), " \
            f"got {validation_result.strategy_match}"
        
        # Verify normalized names are equal
        assert validation_result.declared_normalized == validation_result.applied_normalized, \
            f"Expected normalized names to be equal: " \
            f"declared='{validation_result.declared_normalized}', " \
            f"applied='{validation_result.applied_normalized}'"
        
        print("✅ Test 7.4 passed: Normalization equivalence")
    
    def test_fooling_attack_filtering(self):
        """
        Test 7.5: Test fooling attack filtering
        
        Requirements: 2.1
        
        This test validates that fooling attacks (badseq, badsum) are
        filtered from the strategy name, leaving only core attacks.
        """
        # Create detected_attacks with multisplit + fooling attacks
        detected_attacks = ['multisplit', 'badseq', 'badsum']
        
        # Test PCAPAnalyzer._determine_strategy_type_from_attacks
        strategy_type, combo_attacks = self.analyzer._determine_strategy_type_from_attacks(
            detected_attacks
        )
        
        # Verify strategy_type = "multisplit" (fooling attacks filtered)
        assert strategy_type == "multisplit", \
            f"Expected 'multisplit', got '{strategy_type}'"
        
        # Verify combo_attacks = ['multisplit'] (no fooling attacks)
        assert combo_attacks == ['multisplit'], \
            f"Expected ['multisplit'], got {combo_attacks}"
        
        # Create PCAPAnalysisResult
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="/tmp/test_fooling.pcap",
            packet_count=6,
            detected_attacks=detected_attacks,
            strategy_type=strategy_type,
            combo_attacks=combo_attacks,
            parameters={'split_pos': 3},
            split_positions=[3, 5],
            fake_packets_detected=0,
            sni_values=['example.com']
        )
        
        # Run StrategyValidator.validate()
        declared_strategy = "multisplit"
        validation_result = self.validator.validate(
            declared_strategy_name=declared_strategy,
            pcap_analysis=pcap_analysis
        )
        
        # Verify strategy_match = True
        assert validation_result.strategy_match, \
            f"Expected strategy_match=True, got {validation_result.strategy_match}"
        
        assert validation_result.applied_strategy == "multisplit", \
            f"Expected 'multisplit', got '{validation_result.applied_strategy}'"
        
        print("✅ Test 7.5 passed: Fooling attack filtering")
    
    def test_edge_case_empty_attacks(self):
        """
        Additional test: Edge case with empty detected_attacks
        
        This validates that empty attack lists are handled gracefully.
        """
        # Test with empty detected_attacks
        strategy_type, combo_attacks = self.analyzer._determine_strategy_type_from_attacks([])
        
        assert strategy_type is None, \
            f"Expected None for empty attacks, got '{strategy_type}'"
        
        assert combo_attacks == [], \
            f"Expected empty list for combo_attacks, got {combo_attacks}"
        
        print("✅ Additional test passed: Edge case with empty attacks")
    
    def test_edge_case_only_fooling_attacks(self):
        """
        Additional test: Edge case with only fooling attacks
        
        This validates that when only fooling attacks are present,
        the first one is returned as strategy_type.
        """
        # Test with only fooling attacks
        detected_attacks = ['badseq', 'badsum']
        strategy_type, combo_attacks = self.analyzer._determine_strategy_type_from_attacks(
            detected_attacks
        )
        
        assert strategy_type == 'badseq', \
            f"Expected 'badseq' (first fooling attack), got '{strategy_type}'"
        
        assert combo_attacks == [], \
            f"Expected empty combo_attacks, got {combo_attacks}"
        
        print("✅ Additional test passed: Edge case with only fooling attacks")
    
    def test_special_combo_fakeddisorder(self):
        """
        Additional test: Special combo fake + disorder → fakeddisorder
        
        This validates the special case handling for fake + disorder.
        """
        # Test fake + disorder special case
        detected_attacks = ['fake', 'disorder']
        strategy_type, combo_attacks = self.analyzer._determine_strategy_type_from_attacks(
            detected_attacks
        )
        
        assert strategy_type == 'fakeddisorder', \
            f"Expected 'fakeddisorder', got '{strategy_type}'"
        
        assert set(combo_attacks) == {'fake', 'disorder'}, \
            f"Expected ['fake', 'disorder'], got {combo_attacks}"
        
        # Test with reversed order
        detected_attacks_reversed = ['disorder', 'fake']
        strategy_type2, combo_attacks2 = self.analyzer._determine_strategy_type_from_attacks(
            detected_attacks_reversed
        )
        
        assert strategy_type2 == 'fakeddisorder', \
            f"Expected 'fakeddisorder' (order-independent), got '{strategy_type2}'"
        
        print("✅ Additional test passed: Special combo fakeddisorder")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
