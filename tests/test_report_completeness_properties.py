"""
Property-based tests for validation report completeness.

Feature: strategy-testing-production-parity, Property 6: Validation reports are complete
Validates: Requirements 4.1, 4.2, 4.3, 4.4

For any completed test, the validation report must contain: test outcome, connection metrics
(latency, retransmissions, packet_count), PCAP analysis results, and applied strategy details.
"""

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
def any_strategy_name(draw):
    """Generate any strategy name."""
    # Generate either single attack or combo
    is_combo = draw(st.booleans())
    
    if is_combo:
        # Generate 2-4 component attacks
        num_components = draw(st.integers(min_value=2, max_value=4))
        components = draw(st.lists(
            valid_attack_name(),
            min_size=num_components,
            max_size=num_components,
            unique=True
        ))
        components = sorted(components)
        return f"smart_combo_{'_'.join(components)}"
    else:
        return draw(valid_attack_name())


@st.composite
def pcap_analysis_result(draw):
    """Generate a PCAPAnalysisResult with random data."""
    detected_attacks = draw(st.lists(
        valid_attack_name(),
        min_size=0,
        max_size=4,
        unique=True
    ))
    
    packet_count = draw(st.integers(min_value=0, max_value=1000))
    
    # Generate parameters (may be empty)
    has_params = draw(st.booleans())
    if has_params:
        parameters = {
            'split_pos': draw(st.integers(min_value=1, max_value=10)),
            'ttl': draw(st.integers(min_value=1, max_value=64))
        }
    else:
        parameters = {}
    
    return PCAPAnalysisResult(
        pcap_file="/tmp/test.pcap",
        packet_count=packet_count,
        detected_attacks=detected_attacks,
        parameters=parameters,
        split_positions=[draw(st.integers(min_value=1, max_value=10))] if detected_attacks else [],
        fake_packets_detected=draw(st.integers(min_value=0, max_value=5)),
        sni_values=['example.com'] if detected_attacks else [],
        analysis_time=draw(st.floats(min_value=0.01, max_value=1.0)),
        analyzer_version="1.0"
    )


# ============================================================================
# Property Tests for Report Completeness
# ============================================================================

class TestReportCompletenessProperty:
    """
    **Feature: strategy-testing-production-parity, Property 6: Validation reports are complete**
    **Validates: Requirements 4.1, 4.2, 4.3, 4.4**
    
    Property: For any completed test, the validation report must contain: test outcome,
    connection metrics (latency, retransmissions, packet_count), PCAP analysis results,
    and applied strategy details.
    """
    
    @given(
        strategy=any_strategy_name(),
        pcap=pcap_analysis_result()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_validation_result_has_all_required_fields(self, strategy, pcap):
        """
        Test that ValidationResult has all required fields.
        
        For any validation, the result must contain all required fields:
        - is_valid (test outcome)
        - all_attacks_applied (completeness check)
        - declared_strategy
        - applied_strategy
        - strategy_match
        - parameters_extracted
        - parameter_count
        - warnings
        - errors
        - recommendations
        - missing_components
        
        Validates: Requirements 4.1, 4.2, 4.3, 4.4
        """
        # Create validator
        validator = StrategyValidator()
        
        # Validate
        result = validator.validate(strategy, pcap)
        
        # Check that all required fields are present
        assert hasattr(result, 'is_valid'), "ValidationResult must have 'is_valid' field"
        assert hasattr(result, 'all_attacks_applied'), "ValidationResult must have 'all_attacks_applied' field"
        assert hasattr(result, 'declared_strategy'), "ValidationResult must have 'declared_strategy' field"
        assert hasattr(result, 'applied_strategy'), "ValidationResult must have 'applied_strategy' field"
        assert hasattr(result, 'strategy_match'), "ValidationResult must have 'strategy_match' field"
        assert hasattr(result, 'parameters_extracted'), "ValidationResult must have 'parameters_extracted' field"
        assert hasattr(result, 'parameter_count'), "ValidationResult must have 'parameter_count' field"
        assert hasattr(result, 'warnings'), "ValidationResult must have 'warnings' field"
        assert hasattr(result, 'errors'), "ValidationResult must have 'errors' field"
        assert hasattr(result, 'recommendations'), "ValidationResult must have 'recommendations' field"
        assert hasattr(result, 'missing_components'), "ValidationResult must have 'missing_components' field"
    
    @given(
        strategy=any_strategy_name(),
        pcap=pcap_analysis_result()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_validation_result_fields_have_correct_types(self, strategy, pcap):
        """
        Test that ValidationResult fields have correct types.
        
        For any validation, the result fields must have the correct types.
        
        Validates: Requirements 4.1, 4.2, 4.3, 4.4
        """
        # Create validator
        validator = StrategyValidator()
        
        # Validate
        result = validator.validate(strategy, pcap)
        
        # Check field types
        assert isinstance(result.is_valid, bool), "is_valid must be bool"
        assert isinstance(result.all_attacks_applied, bool), "all_attacks_applied must be bool"
        assert isinstance(result.declared_strategy, str), "declared_strategy must be str"
        assert isinstance(result.applied_strategy, str), "applied_strategy must be str"
        assert isinstance(result.strategy_match, bool), "strategy_match must be bool"
        assert isinstance(result.parameters_extracted, bool), "parameters_extracted must be bool"
        assert isinstance(result.parameter_count, int), "parameter_count must be int"
        assert isinstance(result.warnings, list), "warnings must be list"
        assert isinstance(result.errors, list), "errors must be list"
        assert isinstance(result.recommendations, list), "recommendations must be list"
        assert isinstance(result.missing_components, list), "missing_components must be list"
    
    @given(
        strategy=any_strategy_name(),
        pcap=pcap_analysis_result()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_declared_strategy_is_recorded(self, strategy, pcap):
        """
        Test that declared strategy is recorded in the report.
        
        For any validation, the declared_strategy field must match
        the strategy name passed to validate().
        
        Validates: Requirement 4.4
        """
        # Create validator
        validator = StrategyValidator()
        
        # Validate
        result = validator.validate(strategy, pcap)
        
        # Check that declared strategy is recorded
        assert result.declared_strategy == strategy, \
            f"declared_strategy should be '{strategy}', but got '{result.declared_strategy}'"
    
    @given(
        strategy=any_strategy_name(),
        pcap=pcap_analysis_result()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_applied_strategy_is_determined(self, strategy, pcap):
        """
        Test that applied strategy is determined from PCAP.
        
        For any validation, the applied_strategy field must be set
        based on the detected attacks in PCAP.
        
        Validates: Requirement 4.4
        """
        # Create validator
        validator = StrategyValidator()
        
        # Validate
        result = validator.validate(strategy, pcap)
        
        # Check that applied strategy is set
        assert result.applied_strategy is not None, \
            "applied_strategy must be set"
        assert isinstance(result.applied_strategy, str), \
            "applied_strategy must be a string"
        assert len(result.applied_strategy) > 0, \
            "applied_strategy must not be empty"
    
    @given(
        strategy=any_strategy_name(),
        pcap=pcap_analysis_result()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_parameter_count_matches_extracted_parameters(self, strategy, pcap):
        """
        Test that parameter_count matches the number of extracted parameters.
        
        For any validation, the parameter_count field must match
        the number of non-null parameters in the PCAP analysis.
        
        Validates: Requirement 4.3
        """
        # Create validator
        validator = StrategyValidator()
        
        # Validate
        result = validator.validate(strategy, pcap)
        
        # Count non-null parameters in PCAP
        expected_count = len([v for v in pcap.parameters.values() if v is not None])
        
        # Check that parameter_count matches
        assert result.parameter_count == expected_count, \
            f"parameter_count should be {expected_count}, but got {result.parameter_count}"
    
    @given(
        strategy=any_strategy_name(),
        pcap=pcap_analysis_result()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_warnings_list_is_always_present(self, strategy, pcap):
        """
        Test that warnings list is always present (even if empty).
        
        For any validation, the warnings field must be a list
        (may be empty if no warnings).
        
        Validates: Requirement 4.4
        """
        # Create validator
        validator = StrategyValidator()
        
        # Validate
        result = validator.validate(strategy, pcap)
        
        # Check that warnings is a list
        assert isinstance(result.warnings, list), \
            "warnings must be a list"
    
    @given(
        strategy=any_strategy_name(),
        pcap=pcap_analysis_result()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_errors_list_is_always_present(self, strategy, pcap):
        """
        Test that errors list is always present (even if empty).
        
        For any validation, the errors field must be a list
        (may be empty if no errors).
        
        Validates: Requirement 4.4
        """
        # Create validator
        validator = StrategyValidator()
        
        # Validate
        result = validator.validate(strategy, pcap)
        
        # Check that errors is a list
        assert isinstance(result.errors, list), \
            "errors must be a list"
    
    @given(
        strategy=any_strategy_name(),
        pcap=pcap_analysis_result()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_recommendations_list_is_always_present(self, strategy, pcap):
        """
        Test that recommendations list is always present (even if empty).
        
        For any validation, the recommendations field must be a list
        (may be empty if no recommendations).
        
        Validates: Requirement 4.4
        """
        # Create validator
        validator = StrategyValidator()
        
        # Validate
        result = validator.validate(strategy, pcap)
        
        # Check that recommendations is a list
        assert isinstance(result.recommendations, list), \
            "recommendations must be a list"
    
    @given(
        strategy=any_strategy_name(),
        pcap=pcap_analysis_result()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_missing_components_list_is_always_present(self, strategy, pcap):
        """
        Test that missing_components list is always present (even if empty).
        
        For any validation, the missing_components field must be a list
        (may be empty if all components are present).
        
        Validates: Requirement 4.4
        """
        # Create validator
        validator = StrategyValidator()
        
        # Validate
        result = validator.validate(strategy, pcap)
        
        # Check that missing_components is a list
        assert isinstance(result.missing_components, list), \
            "missing_components must be a list"
    
    @given(
        strategy=any_strategy_name(),
        pcap=pcap_analysis_result()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_completeness_check_is_performed(self, strategy, pcap):
        """
        Test that completeness check is performed.
        
        For any validation, the all_attacks_applied field must be set
        based on whether all declared attacks were detected.
        
        Validates: Requirement 4.1
        """
        # Create validator
        validator = StrategyValidator()
        
        # Validate
        result = validator.validate(strategy, pcap)
        
        # Check that all_attacks_applied is a boolean
        assert isinstance(result.all_attacks_applied, bool), \
            "all_attacks_applied must be a boolean"
        
        # Decompose declared strategy
        declared_attacks = validator._decompose_strategy(strategy)
        detected_attacks = pcap.detected_attacks
        
        # Check if all declared attacks are in detected (accounting for equivalence)
        # Note: With normalization, 'multisplit' and 'split' are equivalent
        # The validator's _check_completeness method handles this
        expected_complete = validator._check_completeness(declared_attacks, detected_attacks)
        
        # Verify that all_attacks_applied matches expectation
        assert result.all_attacks_applied == expected_complete, \
            f"all_attacks_applied should be {expected_complete}, but got {result.all_attacks_applied}"
    
    @given(
        strategy=any_strategy_name(),
        pcap=pcap_analysis_result()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_strategy_match_is_determined(self, strategy, pcap):
        """
        Test that strategy match is determined.
        
        For any validation, the strategy_match field must be set
        based on whether declared strategy matches applied strategy.
        
        Validates: Requirement 4.2
        """
        # Create validator
        validator = StrategyValidator()
        
        # Validate
        result = validator.validate(strategy, pcap)
        
        # Check that strategy_match is a boolean
        assert isinstance(result.strategy_match, bool), \
            "strategy_match must be a boolean"
        
        # Verify that strategy_match is consistent with normalized comparison
        # Note: With normalization, 'multisplit' and 'split' are equivalent
        # The strategy_match field uses normalized comparison
        from core.validation.strategy_name_normalizer import StrategyNameNormalizer
        
        declared_norm = StrategyNameNormalizer.normalize(result.declared_strategy)
        applied_norm = StrategyNameNormalizer.normalize(result.applied_strategy)
        
        if declared_norm == applied_norm:
            assert result.strategy_match, \
                f"strategy_match should be True when normalized names match: " \
                f"declared={result.declared_strategy} (norm={declared_norm}), " \
                f"applied={result.applied_strategy} (norm={applied_norm})"
        else:
            assert not result.strategy_match, \
                f"strategy_match should be False when normalized names differ: " \
                f"declared={result.declared_strategy} (norm={declared_norm}), " \
                f"applied={result.applied_strategy} (norm={applied_norm})"
    
    @given(
        strategy=any_strategy_name(),
        pcap=pcap_analysis_result()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_validation_result_is_never_none(self, strategy, pcap):
        """
        Test that validation result is never None.
        
        For any validation, the validate() method must return
        a ValidationResult object (never None).
        
        Validates: Requirement 4.4
        """
        # Create validator
        validator = StrategyValidator()
        
        # Validate
        result = validator.validate(strategy, pcap)
        
        # Check that result is not None
        assert result is not None, \
            "validate() must return a ValidationResult, not None"
        
        # Check that result is a ValidationResult
        assert isinstance(result, ValidationResult), \
            f"validate() must return a ValidationResult, not {type(result)}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
