"""
Property-Based Tests for Edge Case Handling

Feature: pcap-validator-combo-detection
Property 7: Edge case handling
Validates: Requirements 7.1, 7.3, 7.4, 7.5

Tests that the system handles edge cases gracefully:
- Empty/None inputs in PCAPAnalyzer
- Empty/None inputs in StrategyValidator
- Special characters in strategy names
"""

import pytest
from hypothesis import given, strategies as st, settings, HealthCheck
from typing import Optional, List

from core.pcap.analyzer import PCAPAnalyzer
from core.validation.strategy_validator import StrategyValidator
from core.validation.strategy_name_normalizer import StrategyNameNormalizer
from core.test_result_models import PCAPAnalysisResult


# ============================================================================
# GENERATORS
# ============================================================================

@st.composite
def edge_case_attack_lists(draw) -> Optional[List[str]]:
    """
    Generate edge case attack lists for testing.
    
    Generates:
    - None
    - Empty list
    - List with only fooling attacks (badsum, badseq, ttl_manipulation)
    - Normal attack lists
    
    Note: seqovl is NOT a fooling attack - it's a core attack
    """
    case_type = draw(st.sampled_from([
        'none',
        'empty',
        'only_fooling',
        'normal'
    ]))
    
    if case_type == 'none':
        return None
    elif case_type == 'empty':
        return []
    elif case_type == 'only_fooling':
        # Only fooling attacks (NOT including seqovl - it's a core attack)
        fooling_attacks = ['badsum', 'badseq', 'ttl_manipulation']
        return draw(st.lists(
            st.sampled_from(fooling_attacks),
            min_size=1,
            max_size=3
        ))
    else:
        # Normal attack list
        attacks = ['split', 'fake', 'disorder', 'multisplit', 'seqovl']
        return draw(st.lists(
            st.sampled_from(attacks),
            min_size=1,
            max_size=3
        ))


@st.composite
def edge_case_strategy_names(draw) -> str:
    """
    Generate edge case strategy names for testing.
    
    Generates:
    - Empty strings
    - Strings with special characters
    - Normal strategy names
    """
    case_type = draw(st.sampled_from([
        'empty',
        'whitespace',
        'special_chars',
        'normal'
    ]))
    
    if case_type == 'empty':
        return ""
    elif case_type == 'whitespace':
        return draw(st.text(alphabet=' \t\n', min_size=1, max_size=5))
    elif case_type == 'special_chars':
        # Strategy name with special characters
        base_name = draw(st.sampled_from(['split', 'fake', 'disorder']))
        special_chars = draw(st.text(
            alphabet='!@#$%^&*()+=[]{}|;:,.<>?/',
            min_size=1,
            max_size=3
        ))
        return f"{base_name}{special_chars}"
    else:
        # Normal strategy name
        return draw(st.sampled_from([
            'split',
            'fake',
            'disorder',
            'smart_combo_split_fake',
            'smart_combo_disorder_multisplit'
        ]))


@st.composite
def edge_case_pcap_analysis(draw) -> Optional[PCAPAnalysisResult]:
    """
    Generate edge case PCAPAnalysisResult for testing.
    
    Generates:
    - None
    - Result with strategy_type = 'unknown'
    - Result with strategy_type = None
    - Normal result
    """
    case_type = draw(st.sampled_from([
        'none',
        'unknown_strategy',
        'none_strategy',
        'normal'
    ]))
    
    if case_type == 'none':
        return None
    
    # Generate base result
    detected_attacks = draw(st.lists(
        st.sampled_from(['split', 'fake', 'disorder']),
        min_size=0,
        max_size=3
    ))
    
    if case_type == 'unknown_strategy':
        strategy_type = 'unknown'
    elif case_type == 'none_strategy':
        strategy_type = None
    else:
        strategy_type = 'split' if detected_attacks else None
    
    return PCAPAnalysisResult(
        pcap_file="test.pcap",
        packet_count=draw(st.integers(min_value=0, max_value=100)),
        detected_attacks=detected_attacks,
        strategy_type=strategy_type,
        combo_attacks=[],
        parameters={},
        split_positions=[],
        fake_packets_detected=0,
        sni_values=[],
        analysis_time=0.0,
        analyzer_version="1.0",
        errors=[],
        warnings=[]
    )


# ============================================================================
# PROPERTY TESTS
# ============================================================================

@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(detected_attacks=edge_case_attack_lists())
def test_property_pcap_analyzer_edge_cases(detected_attacks):
    """
    **Feature: pcap-validator-combo-detection, Property 7: Edge case handling**
    **Validates: Requirements 7.1, 7.2**
    
    Property: For any edge case input (None, empty, only fooling attacks),
    PCAPAnalyzer._determine_strategy_type_from_attacks must handle it gracefully
    without raising exceptions and return appropriate default values.
    
    Edge cases tested:
    - None detected_attacks → return (None, [])
    - Empty detected_attacks → return (None, [])
    - Only fooling attacks → return (first_attack, [])
    """
    analyzer = PCAPAnalyzer()
    
    # Should not raise any exceptions
    try:
        strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks(
            detected_attacks
        )
        
        # Verify return types are correct
        assert strategy_type is None or isinstance(strategy_type, str)
        assert isinstance(combo_attacks, list)
        
        # Verify edge case handling
        if detected_attacks is None or not detected_attacks:
            # Requirement 7.1: Empty/None → return (None, [])
            assert strategy_type is None
            assert combo_attacks == []
        elif all(attack in {'badsum', 'badseq', 'ttl_manipulation'} 
                 for attack in detected_attacks):
            # Requirement 7.2: Only fooling attacks → return (first_attack, [])
            # FOOLING_LABELS = {'badsum', 'badseq', 'ttl_manipulation'}
            assert strategy_type == detected_attacks[0]
            assert combo_attacks == []
        else:
            # Normal case - should have strategy_type
            assert strategy_type is not None
            
    except Exception as e:
        pytest.fail(f"Edge case handling raised exception: {e}")


@settings(max_examples=100)
@given(
    declared_strategy=edge_case_strategy_names(),
    pcap_analysis=edge_case_pcap_analysis()
)
def test_property_validator_edge_cases(declared_strategy, pcap_analysis):
    """
    **Feature: pcap-validator-combo-detection, Property 7: Edge case handling**
    **Validates: Requirements 7.3, 7.4**
    
    Property: For any edge case input (None pcap_analysis, empty declared_strategy,
    strategy_type='unknown', strategy_type=None), StrategyValidator.validate must
    handle it gracefully without raising exceptions and return appropriate defaults.
    
    Edge cases tested:
    - None pcap_analysis → set applied_strategy = 'unknown'
    - Empty declared_strategy → handle gracefully without errors
    - strategy_type = 'unknown' → fall back to reconstruction
    - strategy_type = None → fall back to reconstruction
    """
    validator = StrategyValidator()
    
    # Should not raise any exceptions
    try:
        result = validator.validate(declared_strategy, pcap_analysis)
        
        # Verify result is valid ValidationResult
        assert hasattr(result, 'is_valid')
        assert hasattr(result, 'applied_strategy')
        assert hasattr(result, 'strategy_match')
        
        # Verify edge case handling
        if pcap_analysis is None:
            # Requirement 7.4: None pcap_analysis → applied_strategy = 'unknown'
            assert result.applied_strategy == 'unknown'
            assert result.applied_strategy_source == 'error'
            assert not result.is_valid
        
        if not declared_strategy or declared_strategy.strip() == "":
            # Requirement 7.3: Empty declared_strategy → handle gracefully
            # Should not crash, should have some declared_strategy value
            assert result.declared_strategy is not None
        
        if pcap_analysis and hasattr(pcap_analysis, 'strategy_type'):
            if pcap_analysis.strategy_type == 'unknown':
                # Requirement 7.4: strategy_type='unknown' → fall back to reconstruction
                assert result.applied_strategy_source in ['reconstruction', 'metadata']
            elif pcap_analysis.strategy_type is None:
                # Requirement 7.4: strategy_type=None → fall back to reconstruction
                assert result.applied_strategy_source in ['reconstruction', 'metadata']
                
    except Exception as e:
        pytest.fail(f"Edge case handling raised exception: {e}")


@settings(max_examples=100)
@given(strategy_name=edge_case_strategy_names())
def test_property_normalizer_special_characters(strategy_name):
    """
    **Feature: pcap-validator-combo-detection, Property 7: Edge case handling**
    **Validates: Requirements 7.5**
    
    Property: For any strategy name with special characters, empty strings, or
    whitespace, StrategyNameNormalizer.normalize must handle it gracefully
    without raising exceptions.
    
    Edge cases tested:
    - Empty strings → return as-is
    - Whitespace strings → handle gracefully
    - Special characters → clean and log warning
    """
    # Should not raise any exceptions
    try:
        normalized = StrategyNameNormalizer.normalize(strategy_name)
        
        # Verify return type is correct
        assert isinstance(normalized, str)
        
        # Verify edge case handling
        if not strategy_name or strategy_name.strip() == "":
            # Empty/whitespace → should return something (possibly 'unknown')
            assert normalized is not None
        
        # Special characters should be handled (cleaned or kept)
        # The important thing is no exception is raised
        
    except Exception as e:
        pytest.fail(f"Special character handling raised exception: {e}")


@settings(max_examples=100)
@given(strategy_name=st.text(min_size=0, max_size=50))
def test_property_normalizer_never_crashes(strategy_name):
    """
    **Feature: pcap-validator-combo-detection, Property 7: Edge case handling**
    **Validates: Requirements 7.5**
    
    Property: For ANY string input (including arbitrary Unicode, special chars, etc.),
    StrategyNameNormalizer.normalize must never raise an exception.
    
    This is a stronger version of the special character test that uses completely
    arbitrary strings to ensure robustness.
    """
    # Should NEVER raise any exceptions, no matter what the input
    try:
        normalized = StrategyNameNormalizer.normalize(strategy_name)
        
        # Verify return type is correct
        assert isinstance(normalized, str)
        
    except Exception as e:
        pytest.fail(
            f"Normalizer crashed on input '{strategy_name}': {e}. "
            f"Normalizer must handle ALL inputs gracefully."
        )


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

def test_edge_case_integration_none_pcap_analysis():
    """
    Integration test: Validate with None pcap_analysis.
    
    Requirement 7.4: Handle None pcap_analysis → set applied_strategy = 'unknown'
    """
    validator = StrategyValidator()
    result = validator.validate("split", None)
    
    assert result.applied_strategy == "unknown"
    assert result.applied_strategy_source == "error"
    assert not result.is_valid
    assert "PCAP analysis is None" in result.errors


def test_edge_case_integration_empty_declared_strategy():
    """
    Integration test: Validate with empty declared_strategy.
    
    Requirement 7.3: Handle empty declared_strategy → handle gracefully without errors
    """
    validator = StrategyValidator()
    pcap_analysis = PCAPAnalysisResult(
        pcap_file="test.pcap",
        packet_count=10,
        detected_attacks=['split'],
        strategy_type='split',
        combo_attacks=[],
        parameters={},
        split_positions=[3],
        fake_packets_detected=0,
        sni_values=[],
        analysis_time=0.0,
        analyzer_version="1.0",
        errors=[],
        warnings=[]
    )
    
    # Should not crash with empty string
    result = validator.validate("", pcap_analysis)
    assert result.declared_strategy == "unknown"
    
    # Should not crash with whitespace
    result = validator.validate("   ", pcap_analysis)
    assert result.declared_strategy == "unknown"


def test_edge_case_integration_unknown_strategy_type():
    """
    Integration test: Validate with strategy_type = 'unknown'.
    
    Requirement 7.4: Handle strategy_type = 'unknown' → fall back to reconstruction
    """
    validator = StrategyValidator()
    pcap_analysis = PCAPAnalysisResult(
        pcap_file="test.pcap",
        packet_count=10,
        detected_attacks=['split', 'fake'],
        strategy_type='unknown',  # Edge case
        combo_attacks=[],
        parameters={},
        split_positions=[3],
        fake_packets_detected=1,
        sni_values=[],
        analysis_time=0.0,
        analyzer_version="1.0",
        errors=[],
        warnings=[]
    )
    
    result = validator.validate("smart_combo_split_fake", pcap_analysis)
    
    # Should fall back to reconstruction
    assert result.applied_strategy_source == "reconstruction"
    # Should reconstruct from detected_attacks
    assert result.applied_strategy in ['smart_combo_fake_split', 'smart_combo_split_fake']


def test_edge_case_integration_none_strategy_type():
    """
    Integration test: Validate with strategy_type = None.
    
    Requirement 7.4: Handle strategy_type = None → fall back to reconstruction
    """
    validator = StrategyValidator()
    pcap_analysis = PCAPAnalysisResult(
        pcap_file="test.pcap",
        packet_count=10,
        detected_attacks=['disorder'],
        strategy_type=None,  # Edge case
        combo_attacks=[],
        parameters={},
        split_positions=[],
        fake_packets_detected=0,
        sni_values=[],
        analysis_time=0.0,
        analyzer_version="1.0",
        errors=[],
        warnings=[]
    )
    
    result = validator.validate("disorder", pcap_analysis)
    
    # Should fall back to reconstruction
    assert result.applied_strategy_source == "reconstruction"
    # Should reconstruct from detected_attacks
    assert result.applied_strategy == "disorder"


def test_edge_case_integration_special_characters():
    """
    Integration test: Normalize strategy name with special characters.
    
    Requirement 7.5: Handle special characters → clean and log warning
    """
    # Should handle special characters gracefully
    result = StrategyNameNormalizer.normalize("split@#$%")
    assert isinstance(result, str)
    # Special chars should be removed
    assert "@" not in result
    assert "#" not in result
    
    # Should handle empty after cleaning
    result = StrategyNameNormalizer.normalize("@#$%")
    assert isinstance(result, str)
