"""
Property-based tests for StrategyValidator priority and normalization.

Feature: pcap-validator-combo-detection
Tests Property 4: Validator priority and normalization
Validates: Requirements 4.1, 4.3, 4.4, 4.5
"""

import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck
from typing import List, Optional

from core.validation.strategy_validator import StrategyValidator
from core.test_result_models import PCAPAnalysisResult, ValidationResult


# ============================================================================
# Strategies for generating test data
# ============================================================================

@st.composite
def attack_list(draw, min_size=0, max_size=5):
    """Generate a list of attack names."""
    attacks = ['split', 'multisplit', 'fake', 'disorder', 'badsum', 'badseq', 'seqovl']
    size = draw(st.integers(min_value=min_size, max_value=max_size))
    return draw(st.lists(
        st.sampled_from(attacks),
        min_size=size,
        max_size=size,
        unique=True
    ))


@st.composite
def strategy_name_from_attacks(draw, attacks: List[str]):
    """Generate a strategy name from a list of attacks."""
    if not attacks:
        return "none"
    
    # Filter out fooling attacks for strategy name
    fooling = {'badsum', 'badseq', 'seqovl'}
    main_attacks = [a for a in attacks if a not in fooling]
    
    if not main_attacks:
        return attacks[0]
    
    if len(main_attacks) == 1:
        return main_attacks[0]
    
    # Sort for consistent naming
    sorted_attacks = sorted(main_attacks)
    
    # Optionally add prefix
    use_prefix = draw(st.booleans())
    if use_prefix:
        return f"smart_combo_{'_'.join(sorted_attacks)}"
    else:
        return '_'.join(sorted_attacks)


@st.composite
def pcap_analysis_with_priority_sources(draw):
    """
    Generate PCAPAnalysisResult with different priority sources available.
    
    This tests the 3-tier priority logic:
    1. executed_attacks_from_log (metadata)
    2. strategy_type (from PCAPAnalyzer)
    3. detected_attacks (for reconstruction)
    """
    # Generate base attacks
    detected = draw(attack_list(min_size=1, max_size=4))
    
    # Determine which sources are available
    has_metadata = draw(st.booleans())
    has_strategy_type = draw(st.booleans())
    
    # Generate strategy names
    metadata_strategy = None
    if has_metadata:
        metadata_strategy = draw(strategy_name_from_attacks(detected))
    
    strategy_type = None
    if has_strategy_type:
        # strategy_type might be 'unknown'
        is_unknown = draw(st.booleans())
        if is_unknown:
            strategy_type = 'unknown'
        else:
            strategy_type = draw(strategy_name_from_attacks(detected))
    
    return PCAPAnalysisResult(
        pcap_file="test.pcap",
        packet_count=10,
        detected_attacks=detected,
        executed_attacks_from_log=metadata_strategy,
        strategy_type=strategy_type,
        combo_attacks=[a for a in detected if a not in {'badsum', 'badseq', 'seqovl'}]
    )


# ============================================================================
# Property Test: Validator Priority and Normalization (Property 4)
# ============================================================================

class TestValidatorPriorityAndNormalization:
    """
    **Feature: pcap-validator-combo-detection, Property 4: Validator priority and normalization**
    **Validates: Requirements 4.1, 4.3, 4.4, 4.5**
    
    Property: For any validation, the StrategyValidator must:
    1. Use executed_attacks_from_log if available (priority 1)
    2. Else use strategy_type if not 'unknown' (priority 2)
    3. Else reconstruct from detected_attacks (priority 3)
    4. Normalize both declared and applied names before comparison
    """
    
    @given(pcap_analysis=pcap_analysis_with_priority_sources())
    @settings(max_examples=100)
    def test_priority_source_selection(self, pcap_analysis):
        """
        Test that validator uses correct priority source.
        
        Requirement 4.1, 4.3: Priority order must be:
        1. executed_attacks_from_log (metadata)
        2. strategy_type (PCAPAnalyzer)
        3. detected_attacks (reconstruction)
        """
        validator = StrategyValidator()
        
        # Generate a declared strategy name
        declared = "smart_combo_split_fake"
        
        # Validate
        result = validator.validate(declared, pcap_analysis)
        
        # Check that source is correctly determined
        # Requirement 4.1: Track which source was used
        assert hasattr(result, 'applied_strategy_source'), \
            "ValidationResult must have applied_strategy_source field"
        
        # Verify priority logic
        if pcap_analysis.executed_attacks_from_log:
            # Priority 1: Should use metadata
            assert result.applied_strategy_source == "metadata", \
                f"Should use metadata when available, got {result.applied_strategy_source}"
            assert result.applied_strategy == pcap_analysis.executed_attacks_from_log, \
                f"Applied strategy should match metadata"
        
        elif hasattr(pcap_analysis, 'strategy_type') and pcap_analysis.strategy_type:
            if pcap_analysis.strategy_type != 'unknown':
                # Priority 2: Should use strategy_type
                assert result.applied_strategy_source == "pcap_analyzer", \
                    f"Should use pcap_analyzer when metadata not available, got {result.applied_strategy_source}"
                assert result.applied_strategy == pcap_analysis.strategy_type, \
                    f"Applied strategy should match strategy_type"
            else:
                # strategy_type is 'unknown', should fall back to reconstruction
                assert result.applied_strategy_source == "reconstruction", \
                    f"Should use reconstruction when strategy_type is 'unknown', got {result.applied_strategy_source}"
        
        else:
            # Priority 3: Should use reconstruction
            assert result.applied_strategy_source == "reconstruction", \
                f"Should use reconstruction as fallback, got {result.applied_strategy_source}"
    
    @given(
        declared=st.sampled_from([
            "smart_combo_disorder_multisplit",
            "disorder_multisplit",
            "multisplit_disorder",
            "smart_combo_multisplit_disorder"
        ]),
        applied=st.sampled_from([
            "smart_combo_disorder_split",
            "disorder_split",
            "split_disorder",
            "smart_combo_split_disorder"
        ])
    )
    @settings(max_examples=100)
    def test_normalization_equivalence(self, declared, applied):
        """
        Test that normalization makes equivalent strategies match.
        
        Requirement 4.4, 4.5: Strategies that differ only in:
        - Prefix (smart_combo_)
        - Attack variants (multisplit vs split)
        - Attack order
        Should be recognized as equivalent after normalization.
        """
        validator = StrategyValidator()
        
        # Create PCAP analysis with the applied strategy
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="test.pcap",
            packet_count=10,
            detected_attacks=['disorder', 'split'],
            strategy_type=applied,
            combo_attacks=['disorder', 'split']
        )
        
        # Validate
        result = validator.validate(declared, pcap_analysis)
        
        # Check normalization fields
        # Requirement 4.4: Store both original and normalized names
        assert hasattr(result, 'declared_normalized'), \
            "ValidationResult must have declared_normalized field"
        assert hasattr(result, 'applied_normalized'), \
            "ValidationResult must have applied_normalized field"
        
        # Both should normalize to 'disorder_split'
        assert result.declared_normalized == 'disorder_split', \
            f"Declared should normalize to 'disorder_split', got {result.declared_normalized}"
        assert result.applied_normalized == 'disorder_split', \
            f"Applied should normalize to 'disorder_split', got {result.applied_normalized}"
        
        # Requirement 4.5: Normalized comparison should match
        assert result.strategy_match, \
            f"Strategies should match after normalization: {declared} vs {applied}"
    
    @given(pcap_analysis=pcap_analysis_with_priority_sources())
    @settings(max_examples=100)
    def test_normalization_always_applied(self, pcap_analysis):
        """
        Test that normalization is always applied regardless of source.
        
        Requirement 4.4: Normalization must be applied to both declared
        and applied strategy names before comparison.
        """
        validator = StrategyValidator()
        
        # Use a declared strategy with prefix and multisplit
        declared = "smart_combo_disorder_multisplit"
        
        # Validate
        result = validator.validate(declared, pcap_analysis)
        
        # Check that normalization was applied
        assert result.declared_normalized != "", \
            "Declared normalized should not be empty"
        assert result.applied_normalized != "", \
            "Applied normalized should not be empty"
        
        # Declared should normalize to 'disorder_split'
        assert result.declared_normalized == 'disorder_split', \
            f"Expected 'disorder_split', got {result.declared_normalized}"
        
        # Applied normalization depends on what was applied
        # Single attacks may normalize to themselves (e.g., 'disorder' → 'disorder')
        # Combo attacks should be normalized (e.g., 'smart_combo_X_Y' → 'X_Y')
        # The key is that normalization was attempted (field is not empty)
        if result.applied_strategy not in ('none', 'unknown', ''):
            # Normalization should produce a non-empty result
            assert result.applied_normalized != "", \
                f"Applied normalized should not be empty for {result.applied_strategy}"
    
    @given(
        attacks=attack_list(min_size=2, max_size=4)
    )
    @settings(max_examples=100)
    def test_reconstruction_fallback_consistency(self, attacks):
        """
        Test that reconstruction fallback produces consistent results.
        
        Requirement 4.2: When no metadata or strategy_type available,
        validator must reconstruct strategy from detected_attacks.
        """
        # Filter to ensure we have at least one non-fooling attack
        fooling = {'badsum', 'badseq', 'seqovl'}
        main_attacks = [a for a in attacks if a not in fooling]
        assume(len(main_attacks) > 0)
        
        validator = StrategyValidator()
        
        # Create PCAP analysis with only detected_attacks (no metadata or strategy_type)
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="test.pcap",
            packet_count=10,
            detected_attacks=attacks,
            executed_attacks_from_log=None,
            strategy_type=None,
            combo_attacks=main_attacks
        )
        
        # Validate with any declared strategy
        declared = "test_strategy"
        result = validator.validate(declared, pcap_analysis)
        
        # Should use reconstruction
        assert result.applied_strategy_source == "reconstruction", \
            f"Should use reconstruction, got {result.applied_strategy_source}"
        
        # Applied strategy should not be empty
        assert result.applied_strategy != "", \
            "Reconstruction should produce a strategy name"
        
        # Applied strategy should be normalized
        assert result.applied_normalized != "", \
            "Normalized name should not be empty"


# ============================================================================
# Edge Case Tests
# ============================================================================

class TestValidatorEdgeCases:
    """
    Test edge cases in validator priority and normalization.
    """
    
    def test_empty_detected_attacks(self):
        """Test handling of empty detected_attacks list."""
        validator = StrategyValidator()
        
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="test.pcap",
            packet_count=0,
            detected_attacks=[],
            executed_attacks_from_log=None,
            strategy_type=None,
            combo_attacks=[]
        )
        
        result = validator.validate("split", pcap_analysis)
        
        # Should handle gracefully
        assert result.applied_strategy_source in ("reconstruction", "error"), \
            f"Should handle empty attacks, got {result.applied_strategy_source}"
    
    def test_none_pcap_analysis(self):
        """Test handling of None pcap_analysis."""
        validator = StrategyValidator()
        
        # This should raise an error or handle gracefully
        try:
            result = validator.validate("split", None)
            # If it doesn't raise, check that it handled gracefully
            assert not result.is_valid, "Should not be valid with None analysis"
            assert result.applied_strategy_source == "error", \
                "Should indicate error source"
        except (AttributeError, TypeError):
            # Expected - None doesn't have the required attributes
            pass
    
    def test_special_strategy_names(self):
        """Test handling of special strategy names like 'none' and 'unknown'."""
        validator = StrategyValidator()
        
        for special_name in ['none', 'unknown']:
            pcap_analysis = PCAPAnalysisResult(
                pcap_file="test.pcap",
                packet_count=0,
                detected_attacks=[],
                strategy_type=special_name,
                combo_attacks=[]
            )
            
            result = validator.validate(special_name, pcap_analysis)
            
            # Should handle special names
            assert result.declared_normalized == special_name, \
                f"Special name '{special_name}' should normalize to itself"



# ============================================================================
# Property Test: Consistent Logging (Property 6)
# ============================================================================

class TestConsistentLogging:
    """
    **Feature: pcap-validator-combo-detection, Property 6: Consistent logging**
    **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5**
    
    Property: For any validation operation (match, mismatch, using strategy_type,
    fallback, normalization), the system must log with consistent format including
    operation type, strategy names, and source.
    """
    
    @given(pcap_analysis=pcap_analysis_with_priority_sources())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_logging_includes_source(self, pcap_analysis, caplog):
        """
        Test that logging includes source information.
        
        Requirement 6.3, 6.4: Logs must indicate which source was used
        (metadata, pcap_analyzer, reconstruction).
        """
        import logging
        caplog.set_level(logging.INFO)
        
        validator = StrategyValidator()
        declared = "smart_combo_split_fake"
        
        # Validate
        result = validator.validate(declared, pcap_analysis)
        
        # Check that logs contain source information
        log_text = caplog.text.lower()
        
        # Should log which source was used
        if result.applied_strategy_source == "metadata":
            assert "metadata" in log_text, \
                "Logs should mention 'metadata' when using metadata source"
        elif result.applied_strategy_source == "pcap_analyzer":
            assert "pcap" in log_text or "analyzer" in log_text, \
                "Logs should mention PCAPAnalyzer when using that source"
        elif result.applied_strategy_source == "reconstruction":
            assert "reconstruct" in log_text, \
                "Logs should mention 'reconstruction' when using that source"
    
    @given(
        declared=st.sampled_from([
            "smart_combo_disorder_multisplit",
            "split",
            "fake_split"
        ])
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_logging_includes_normalization(self, declared, caplog):
        """
        Test that logging includes normalization steps.
        
        Requirement 6.5: Logs must show "Normalized: X → Y" for both
        declared and applied strategy names.
        """
        import logging
        caplog.set_level(logging.DEBUG)
        
        validator = StrategyValidator()
        
        # Create PCAP analysis
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="test.pcap",
            packet_count=10,
            detected_attacks=['split', 'fake'],
            strategy_type="smart_combo_fake_split",
            combo_attacks=['fake', 'split']
        )
        
        # Validate
        result = validator.validate(declared, pcap_analysis)
        
        # Check that logs contain normalization information
        log_text = caplog.text.lower()
        
        # Should log normalization (at DEBUG level)
        assert "normalized" in log_text or "normalize" in log_text, \
            "Logs should mention normalization"
    
    @given(
        match=st.booleans()
    )
    @settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_logging_match_vs_mismatch(self, match, caplog):
        """
        Test that logging distinguishes between match and mismatch.
        
        Requirement 6.1, 6.2: Logs must clearly indicate whether strategies
        matched or mismatched, with appropriate details.
        """
        import logging
        caplog.set_level(logging.INFO)
        caplog.clear()  # Clear previous logs
        
        validator = StrategyValidator()
        
        if match:
            # Create matching scenario
            declared = "smart_combo_fake_split"
            applied = "smart_combo_fake_split"
        else:
            # Create mismatching scenario
            declared = "smart_combo_disorder_multisplit"
            applied = "smart_combo_fake_split"
        
        pcap_analysis = PCAPAnalysisResult(
            pcap_file="test.pcap",
            packet_count=10,
            detected_attacks=['fake', 'split'],
            strategy_type=applied,
            combo_attacks=['fake', 'split']
        )
        
        # Validate
        result = validator.validate(declared, pcap_analysis)
        
        # Check logs
        log_text = caplog.text.lower()
        
        if match:
            # Should log match
            assert "match" in log_text, \
                "Logs should mention 'match' for matching strategies"
            # Should not log mismatch
            assert "mismatch" not in log_text, \
                "Logs should not mention 'mismatch' for matching strategies"
        else:
            # Should log mismatch
            assert "mismatch" in log_text, \
                "Logs should mention 'mismatch' for mismatching strategies"
    
    @given(pcap_analysis=pcap_analysis_with_priority_sources())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_logging_format_consistency(self, pcap_analysis, caplog):
        """
        Test that logging format is consistent across different scenarios.
        
        All validation operations should produce logs with consistent structure:
        - Operation type (match/mismatch/using/reconstructing)
        - Strategy names
        - Source information
        """
        import logging
        caplog.set_level(logging.DEBUG)
        
        validator = StrategyValidator()
        declared = "test_strategy"
        
        # Validate
        result = validator.validate(declared, pcap_analysis)
        
        # Check that logs are not empty
        assert len(caplog.records) > 0, \
            "Validation should produce log messages"
        
        # Check that logs contain strategy information
        log_text = caplog.text.lower()
        
        # Should mention strategies or validation
        assert any(keyword in log_text for keyword in [
            'strategy', 'validat', 'match', 'applied', 'declared'
        ]), "Logs should contain strategy-related keywords"
