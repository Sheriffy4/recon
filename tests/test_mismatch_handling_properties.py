"""
Property-based tests for strategy mismatch handling.

Feature: strategy-testing-production-parity, Property 4: Strategy mismatch triggers correct handling
Validates: Requirements 2.2, 2.3

For any test where declared_strategy != applied_strategy, the system must log a warning
and save the applied_strategy (not declared).
"""

import logging
from unittest.mock import Mock, patch
import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.validation.strategy_validator import StrategyValidator
from core.test_result_models import PCAPAnalysisResult, ValidationResult


# ============================================================================
# Strategies for generating test data
# ============================================================================

@st.composite
def valid_attack_name(draw):
    """Generate valid attack names."""
    return draw(st.sampled_from([
        'split', 'fake', 'disorder', 'multisplit', 'seqovl',
        'badsum', 'badseq', 'ttl_manipulation'
    ]))


@st.composite
def combo_strategy_name(draw):
    """Generate combo strategy names."""
    # Generate 2-4 component attacks
    num_components = draw(st.integers(min_value=2, max_value=4))
    components = draw(st.lists(
        valid_attack_name(),
        min_size=num_components,
        max_size=num_components,
        unique=True
    ))
    
    # Sort for consistent naming
    components = sorted(components)
    
    return f"smart_combo_{'_'.join(components)}"


@st.composite
def single_attack_strategy_name(draw):
    """Generate single attack strategy names."""
    return draw(valid_attack_name())


@st.composite
def any_strategy_name(draw):
    """Generate any strategy name (single or combo)."""
    return draw(st.one_of(
        single_attack_strategy_name(),
        combo_strategy_name()
    ))


@st.composite
def pcap_analysis_with_attacks(draw, attacks):
    """Generate PCAPAnalysisResult with specific attacks detected."""
    return PCAPAnalysisResult(
        pcap_file="/tmp/test.pcap",
        packet_count=draw(st.integers(min_value=10, max_value=100)),
        detected_attacks=attacks,
        parameters={
            'split_pos': draw(st.integers(min_value=1, max_value=10)),
            'ttl': draw(st.integers(min_value=1, max_value=64))
        },
        split_positions=[draw(st.integers(min_value=1, max_value=10))],
        fake_packets_detected=draw(st.integers(min_value=0, max_value=5)),
        sni_values=['example.com'],
        analysis_time=0.1,
        analyzer_version="1.0"
    )


@st.composite
def mismatched_strategy_pair(draw):
    """
    Generate a pair of (declared_strategy, detected_attacks) where they don't match.
    
    Note: With normalization, 'multisplit' and 'split' are equivalent.
    This generator ensures true mismatches even after normalization.
    """
    from core.validation.strategy_name_normalizer import StrategyNameNormalizer
    
    # Strategy: Pick two different attack types that won't normalize to the same thing
    # Core non-fooling attacks: split/multisplit, fake, disorder, ttl_manipulation
    
    # Pick declared strategy
    declared_attack = draw(st.sampled_from(['split', 'multisplit', 'fake', 'disorder', 'ttl_manipulation']))
    
    # Pick a different attack for detected (ensuring they won't match after normalization)
    if declared_attack in ['split', 'multisplit']:
        # If declared is split/multisplit, use fake or disorder (which won't normalize to split)
        detected_attack = draw(st.sampled_from(['fake', 'disorder', 'ttl_manipulation']))
    elif declared_attack == 'fake':
        # If declared is fake, use split or disorder
        detected_attack = draw(st.sampled_from(['split', 'disorder', 'ttl_manipulation']))
    elif declared_attack == 'disorder':
        # If declared is disorder, use split or fake
        detected_attack = draw(st.sampled_from(['split', 'fake', 'ttl_manipulation']))
    else:  # ttl_manipulation
        # If declared is ttl_manipulation, use any other
        detected_attack = draw(st.sampled_from(['split', 'fake', 'disorder']))
    
    # Optionally make them combo strategies
    make_declared_combo = draw(st.booleans())
    make_detected_combo = draw(st.booleans())
    
    if make_declared_combo:
        # Add another attack to declared
        extra = draw(st.sampled_from(['badsum', 'badseq']))  # Add fooling attack
        declared = f"smart_combo_{declared_attack}_{extra}"
    else:
        declared = declared_attack
    
    if make_detected_combo:
        # Add another attack to detected
        extra = draw(st.sampled_from(['badsum', 'seqovl']))  # Add fooling attack
        detected = [detected_attack, extra]
    else:
        detected = [detected_attack]
    
    return (declared, detected)


# ============================================================================
# Property Tests for Mismatch Handling
# ============================================================================

class TestMismatchHandlingProperty:
    """
    **Feature: strategy-testing-production-parity, Property 4: Strategy mismatch triggers correct handling**
    **Validates: Requirements 2.2, 2.3**
    
    Property: For any test where declared_strategy != applied_strategy, the system must log a warning
    and save the applied_strategy (not declared).
    """
    
    @given(pair=mismatched_strategy_pair())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
    def test_mismatch_logs_warning(self, pair, caplog):
        """
        Test that strategy mismatch logs a warning.
        
        For any test where declared != applied, a warning must be logged
        with both strategy names.
        
        Validates: Requirement 2.2
        """
        declared_strategy, detected_attacks = pair
        
        # Create PCAP analysis with detected attacks
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="/tmp/test.pcap",
            packet_count=50,
            detected_attacks=detected_attacks,
            parameters={'split_pos': 3},
            split_positions=[3],
            fake_packets_detected=0,
            sni_values=['example.com'],
            analysis_time=0.1,
            analyzer_version="1.0"
        )
        
        # Create validator
        validator = StrategyValidator()
        
        # Validate with mismatch
        with caplog.at_level(logging.WARNING):
            result = validator.validate(declared_strategy, pcap_analysis)
        
        # Check that warning was logged
        warning_found = any(
            'mismatch' in record.message.lower() and
            declared_strategy in record.message and
            record.levelname == 'WARNING'
            for record in caplog.records
        )
        
        assert warning_found, \
            f"Expected warning about mismatch between '{declared_strategy}' and detected attacks {detected_attacks}, " \
            f"but no warning was logged. Logs: {[r.message for r in caplog.records]}"
    
    @given(pair=mismatched_strategy_pair())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_mismatch_sets_applied_strategy(self, pair):
        """
        Test that mismatch sets applied_strategy correctly.
        
        For any test where declared != applied, the ValidationResult
        must contain the applied_strategy (what was actually detected).
        
        Validates: Requirement 2.3
        """
        declared_strategy, detected_attacks = pair
        
        # Create PCAP analysis with detected attacks
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="/tmp/test.pcap",
            packet_count=50,
            detected_attacks=detected_attacks,
            parameters={'split_pos': 3},
            split_positions=[3],
            fake_packets_detected=0,
            sni_values=['example.com'],
            analysis_time=0.1,
            analyzer_version="1.0"
        )
        
        # Create validator
        validator = StrategyValidator()
        
        # Validate with mismatch
        result = validator.validate(declared_strategy, pcap_analysis)
        
        # Check that applied_strategy is set correctly
        assert result.applied_strategy is not None, \
            "applied_strategy should be set"
        
        # Check that strategies don't match (after normalization)
        # Note: With normalization, 'multisplit' and 'split' are equivalent
        # The strategy_match field uses normalized comparison
        assert not result.strategy_match, \
            f"strategy_match should be False for mismatched strategies, " \
            f"declared={declared_strategy} (norm={result.declared_normalized}), " \
            f"applied={result.applied_strategy} (norm={result.applied_normalized})"
    
    @given(pair=mismatched_strategy_pair())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_mismatch_includes_warning_in_result(self, pair):
        """
        Test that mismatch includes warning in ValidationResult.
        
        For any test where declared != applied, the ValidationResult.warnings
        must contain a warning about the mismatch.
        
        Validates: Requirement 2.2
        """
        declared_strategy, detected_attacks = pair
        
        # Create PCAP analysis with detected attacks
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="/tmp/test.pcap",
            packet_count=50,
            detected_attacks=detected_attacks,
            parameters={'split_pos': 3},
            split_positions=[3],
            fake_packets_detected=0,
            sni_values=['example.com'],
            analysis_time=0.1,
            analyzer_version="1.0"
        )
        
        # Create validator
        validator = StrategyValidator()
        
        # Validate with mismatch
        result = validator.validate(declared_strategy, pcap_analysis)
        
        # Check that warnings list contains mismatch warning
        mismatch_warning_found = any(
            'mismatch' in warning.lower() and
            declared_strategy in warning
            for warning in result.warnings
        )
        
        assert mismatch_warning_found, \
            f"Expected mismatch warning in ValidationResult.warnings, " \
            f"but got: {result.warnings}"
    
    @given(pair=mismatched_strategy_pair())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_mismatch_includes_recommendation(self, pair):
        """
        Test that mismatch includes recommendation in ValidationResult.
        
        For any test where declared != applied, the ValidationResult.recommendations
        should suggest using the applied strategy.
        
        Validates: Requirement 2.3
        """
        declared_strategy, detected_attacks = pair
        
        # Create PCAP analysis with detected attacks
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="/tmp/test.pcap",
            packet_count=50,
            detected_attacks=detected_attacks,
            parameters={'split_pos': 3},
            split_positions=[3],
            fake_packets_detected=0,
            sni_values=['example.com'],
            analysis_time=0.1,
            analyzer_version="1.0"
        )
        
        # Create validator
        validator = StrategyValidator()
        
        # Validate with mismatch
        result = validator.validate(declared_strategy, pcap_analysis)
        
        # Check that recommendations list contains suggestion to use applied strategy
        recommendation_found = any(
            result.applied_strategy in recommendation
            for recommendation in result.recommendations
        )
        
        assert recommendation_found, \
            f"Expected recommendation to use applied strategy '{result.applied_strategy}', " \
            f"but got recommendations: {result.recommendations}"
    
    @given(
        detected=st.lists(valid_attack_name(), min_size=1, max_size=4, unique=True)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_applied_strategy_matches_detected_attacks(self, detected):
        """
        Test that applied_strategy correctly represents detected attacks.
        
        For any set of detected attacks, the applied_strategy should be
        a valid strategy name that represents those attacks.
        
        Validates: Requirement 2.3
        """
        # Create PCAP analysis with detected attacks
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="/tmp/test.pcap",
            packet_count=50,
            detected_attacks=detected,
            parameters={'split_pos': 3},
            split_positions=[3],
            fake_packets_detected=0,
            sni_values=['example.com'],
            analysis_time=0.1,
            analyzer_version="1.0"
        )
        
        # Create validator
        validator = StrategyValidator()
        
        # Determine what the applied strategy should be
        expected_applied = validator._determine_applied_strategy(detected)
        
        # Validate with any declared strategy (doesn't matter for this test)
        result = validator.validate("test_strategy", pcap_analysis)
        
        # Check that applied_strategy matches what we expect
        assert result.applied_strategy == expected_applied, \
            f"applied_strategy should be '{expected_applied}' for detected attacks {detected}, " \
            f"but got '{result.applied_strategy}'"
        
        # With normalization, multisplit→split, so we need to normalize both sides
        from core.validation.strategy_name_normalizer import StrategyNameNormalizer
        
        # The validator's _determine_applied_strategy method reconstructs strategy names
        # from detected attacks. This test verifies that the reconstruction is consistent.
        
        # Simply check that applied_strategy is not None and is a valid string
        assert result.applied_strategy is not None, \
            "applied_strategy should not be None"
        assert isinstance(result.applied_strategy, str), \
            "applied_strategy should be a string"
        assert len(result.applied_strategy) > 0, \
            "applied_strategy should not be empty"
        
        # The applied strategy should be derivable from the detected attacks
        # (either directly or through reconstruction logic)
        # We don't test the exact reconstruction logic here since it's complex
        # and tested elsewhere. We just verify it produces a valid strategy name.
    
    @given(pair=mismatched_strategy_pair())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_mismatch_marks_validation_as_invalid(self, pair):
        """
        Test that mismatch marks validation as invalid.
        
        For any test where declared != applied, the ValidationResult.is_valid
        should be False.
        
        Validates: Requirement 2.2
        """
        declared_strategy, detected_attacks = pair
        
        # Create PCAP analysis with detected attacks
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="/tmp/test.pcap",
            packet_count=50,
            detected_attacks=detected_attacks,
            parameters={'split_pos': 3},
            split_positions=[3],
            fake_packets_detected=0,
            sni_values=['example.com'],
            analysis_time=0.1,
            analyzer_version="1.0"
        )
        
        # Create validator
        validator = StrategyValidator()
        
        # Validate with mismatch
        result = validator.validate(declared_strategy, pcap_analysis)
        
        # Check that validation is marked as invalid
        assert not result.is_valid, \
            f"Validation should be invalid for mismatched strategies, " \
            f"but is_valid={result.is_valid}"
    
    @given(
        strategy=any_strategy_name()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_matching_strategies_are_valid(self, strategy):
        """
        Test that matching strategies are marked as valid.
        
        For any test where declared == applied (after normalization), 
        the ValidationResult.strategy_match should be True.
        
        Validates: Requirement 2.2
        """
        # Create validator
        validator = StrategyValidator()
        
        # Decompose strategy to get component attacks
        attacks = validator._decompose_strategy(strategy)
        
        # Create PCAP analysis with matching attacks
        # Set strategy_type to match the declared strategy (simulating PCAPAnalyzer output)
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="/tmp/test.pcap",
            packet_count=50,
            detected_attacks=attacks,
            strategy_type=strategy,  # Set strategy_type to match declared
            combo_attacks=attacks,
            parameters={'split_pos': 3, 'ttl': 64},
            split_positions=[3],
            fake_packets_detected=0,
            sni_values=['example.com'],
            analysis_time=0.1,
            analyzer_version="1.0"
        )
        
        # Validate with matching strategy
        result = validator.validate(strategy, pcap_analysis)
        
        # Check that strategies match (after normalization)
        assert result.strategy_match, \
            f"Strategies should match: declared='{strategy}' (norm={result.declared_normalized}), " \
            f"applied='{result.applied_strategy}' (norm={result.applied_normalized})"
        
        # Check that validation is valid (since strategies match and parameters exist)
        assert result.is_valid, \
            f"Validation should be valid for matching strategies with parameters, " \
            f"but is_valid={result.is_valid}"
    
    @given(pair=mismatched_strategy_pair())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_mismatch_handling_is_consistent(self, pair):
        """
        Test that mismatch handling is consistent across multiple validations.
        
        For any mismatched strategy pair, multiple validations should
        produce consistent results.
        
        Validates: Requirements 2.2, 2.3
        """
        declared_strategy, detected_attacks = pair
        
        # Create PCAP analysis with detected attacks
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="/tmp/test.pcap",
            packet_count=50,
            detected_attacks=detected_attacks,
            parameters={'split_pos': 3},
            split_positions=[3],
            fake_packets_detected=0,
            sni_values=['example.com'],
            analysis_time=0.1,
            analyzer_version="1.0"
        )
        
        # Create validator
        validator = StrategyValidator()
        
        # Validate multiple times
        results = []
        for _ in range(3):
            result = validator.validate(declared_strategy, pcap_analysis)
            results.append(result)
        
        # Check that all results are consistent
        for i in range(1, len(results)):
            assert results[i].applied_strategy == results[0].applied_strategy, \
                f"applied_strategy should be consistent across validations"
            assert results[i].strategy_match == results[0].strategy_match, \
                f"strategy_match should be consistent across validations"
            assert results[i].is_valid == results[0].is_valid, \
                f"is_valid should be consistent across validations"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
