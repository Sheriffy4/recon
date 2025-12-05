"""
Property-based tests for missing component reporting.

Feature: strategy-testing-production-parity, Property 10: Missing combo components are reported
Validates: Requirements 7.5

For any combo strategy test where PCAP shows incomplete application, the system must report
which specific component(s) failed to apply.
"""

import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.validation.strategy_validator import StrategyValidator
from core.test_result_models import PCAPAnalysisResult


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
def combo_strategy_with_missing_components(draw):
    """
    Generate a combo strategy where some components are missing in PCAP.
    
    Returns:
        Tuple of (strategy_name, detected_attacks, expected_missing)
    """
    # Generate 2-4 component attacks for the declared strategy
    num_components = draw(st.integers(min_value=2, max_value=4))
    declared_attacks = draw(st.lists(
        valid_attack_name(),
        min_size=num_components,
        max_size=num_components,
        unique=True
    ))
    
    # Sort for consistent naming
    declared_attacks = sorted(declared_attacks)
    strategy_name = f"smart_combo_{'_'.join(declared_attacks)}"
    
    # Remove 1 to N-1 components to create missing components
    num_to_remove = draw(st.integers(min_value=1, max_value=len(declared_attacks) - 1))
    detected_attacks = declared_attacks.copy()
    
    missing_components = []
    for _ in range(num_to_remove):
        if detected_attacks:
            removed = draw(st.sampled_from(detected_attacks))
            detected_attacks.remove(removed)
            missing_components.append(removed)
    
    # Ensure we actually have missing components
    assume(len(missing_components) > 0)
    assume(len(detected_attacks) > 0)  # At least one component detected
    
    return strategy_name, detected_attacks, missing_components


# ============================================================================
# Property Tests for Missing Component Reporting
# ============================================================================

class TestMissingComponentReportingProperty:
    """
    **Feature: strategy-testing-production-parity, Property 10: Missing combo components are reported**
    **Validates: Requirements 7.5**
    
    Property: For any combo strategy test where PCAP shows incomplete application, the system
    must report which specific component(s) failed to apply.
    """
    
    @given(data=combo_strategy_with_missing_components())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_missing_components_are_identified(self, data):
        """
        Test that missing components are identified.
        
        For any combo strategy with missing components, the ValidationResult
        must contain the list of missing components.
        
        Validates: Requirement 7.5
        """
        strategy_name, detected_attacks, expected_missing = data
        
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
        
        # Validate
        result = validator.validate(strategy_name, pcap_analysis)
        
        # Check that missing components are identified
        assert len(result.missing_components) > 0, \
            f"Missing components should be identified, but got empty list"
        
        # Check that all expected missing components are in the result
        for missing in expected_missing:
            assert missing in result.missing_components, \
                f"Expected missing component '{missing}' not found in {result.missing_components}"
    
    @given(data=combo_strategy_with_missing_components())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_missing_components_are_in_errors(self, data):
        """
        Test that missing components are included in errors list.
        
        For any combo strategy with missing components, the ValidationResult.errors
        must contain information about the missing components.
        
        Validates: Requirement 7.5
        """
        strategy_name, detected_attacks, expected_missing = data
        
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
        
        # Validate
        result = validator.validate(strategy_name, pcap_analysis)
        
        # Check that errors list contains information about missing components
        missing_error_found = any(
            'missing' in error.lower() and 'component' in error.lower()
            for error in result.errors
        )
        
        assert missing_error_found, \
            f"Errors list should contain information about missing components, " \
            f"but got: {result.errors}"
    
    @given(data=combo_strategy_with_missing_components())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_missing_components_trigger_recommendations(self, data):
        """
        Test that missing components trigger recommendations.
        
        For any combo strategy with missing components, the ValidationResult.recommendations
        should suggest verifying that all components are being executed.
        
        Validates: Requirement 7.5
        """
        strategy_name, detected_attacks, expected_missing = data
        
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
        
        # Validate
        result = validator.validate(strategy_name, pcap_analysis)
        
        # Check that recommendations list contains suggestion to verify components
        recommendation_found = any(
            'verify' in rec.lower() or 'component' in rec.lower()
            for rec in result.recommendations
        )
        
        assert recommendation_found, \
            f"Recommendations should suggest verifying components, " \
            f"but got: {result.recommendations}"
    
    @given(data=combo_strategy_with_missing_components())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_all_attacks_applied_is_false_when_components_missing(self, data):
        """
        Test that all_attacks_applied is False when components are missing.
        
        For any combo strategy with missing components, the ValidationResult.all_attacks_applied
        must be False.
        
        Validates: Requirement 7.5
        """
        strategy_name, detected_attacks, expected_missing = data
        
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
        
        # Validate
        result = validator.validate(strategy_name, pcap_analysis)
        
        # Check that all_attacks_applied is False
        assert not result.all_attacks_applied, \
            f"all_attacks_applied should be False when components are missing, " \
            f"but got True"
    
    @given(data=combo_strategy_with_missing_components())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_is_valid_is_false_when_components_missing(self, data):
        """
        Test that is_valid is False when components are missing.
        
        For any combo strategy with missing components, the ValidationResult.is_valid
        must be False.
        
        Validates: Requirement 7.5
        """
        strategy_name, detected_attacks, expected_missing = data
        
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
        
        # Validate
        result = validator.validate(strategy_name, pcap_analysis)
        
        # Check that is_valid is False
        assert not result.is_valid, \
            f"is_valid should be False when components are missing, " \
            f"but got True"
    
    @given(
        attacks=st.lists(valid_attack_name(), min_size=2, max_size=4, unique=True)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_no_missing_components_when_all_present(self, attacks):
        """
        Test that no missing components are reported when all are present.
        
        For any combo strategy where all components are detected in PCAP,
        the missing_components list should be empty.
        
        Validates: Requirement 7.5
        """
        # Sort for consistent naming
        attacks = sorted(attacks)
        strategy_name = f"smart_combo_{'_'.join(attacks)}"
        
        # Create PCAP analysis with all attacks detected
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="/tmp/test.pcap",
            packet_count=50,
            detected_attacks=attacks,
            parameters={'split_pos': 3, 'ttl': 64},
            split_positions=[3],
            fake_packets_detected=0,
            sni_values=['example.com'],
            analysis_time=0.1,
            analyzer_version="1.0"
        )
        
        # Create validator
        validator = StrategyValidator()
        
        # Validate
        result = validator.validate(strategy_name, pcap_analysis)
        
        # Check that missing_components is empty
        assert len(result.missing_components) == 0, \
            f"missing_components should be empty when all components are present, " \
            f"but got: {result.missing_components}"
    
    @given(data=combo_strategy_with_missing_components())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_missing_components_count_is_correct(self, data):
        """
        Test that the count of missing components is correct.
        
        For any combo strategy with missing components, the number of items
        in missing_components list should match the number of components
        that are declared but not detected.
        
        Validates: Requirement 7.5
        """
        strategy_name, detected_attacks, expected_missing = data
        
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
        
        # Validate
        result = validator.validate(strategy_name, pcap_analysis)
        
        # Check that the count matches
        assert len(result.missing_components) == len(expected_missing), \
            f"Expected {len(expected_missing)} missing components, " \
            f"but got {len(result.missing_components)}: {result.missing_components}"
    
    @given(data=combo_strategy_with_missing_components())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_missing_components_are_specific(self, data):
        """
        Test that missing components are specific (not generic).
        
        For any combo strategy with missing components, each item in
        missing_components should be a specific attack name, not a generic message.
        
        Validates: Requirement 7.5
        """
        strategy_name, detected_attacks, expected_missing = data
        
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
        
        # Validate
        result = validator.validate(strategy_name, pcap_analysis)
        
        # Check that each missing component is a specific attack name
        valid_attack_names = [
            'split', 'fake', 'disorder', 'multisplit', 'seqovl',
            'badsum', 'badseq', 'ttl_manipulation'
        ]
        
        for missing in result.missing_components:
            assert missing in valid_attack_names, \
                f"Missing component '{missing}' should be a specific attack name, " \
                f"not a generic message"
    
    @given(data=combo_strategy_with_missing_components())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_missing_component_reporting_is_consistent(self, data):
        """
        Test that missing component reporting is consistent across multiple validations.
        
        For any combo strategy with missing components, multiple validations
        should produce consistent missing_components lists.
        
        Validates: Requirement 7.5
        """
        strategy_name, detected_attacks, expected_missing = data
        
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
            result = validator.validate(strategy_name, pcap_analysis)
            results.append(result)
        
        # Check that all results have the same missing components
        for i in range(1, len(results)):
            assert set(results[i].missing_components) == set(results[0].missing_components), \
                f"missing_components should be consistent across validations, " \
                f"but got different results: {results[0].missing_components} vs {results[i].missing_components}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
