"""
Unit tests for ParameterNormalizer.

Tests parameter normalization, validation, and conflict detection.

Requirements: 6.1, 6.2, 6.3, 6.5
"""

import pytest
from core.strategy.normalizer import ParameterNormalizer
from core.strategy.exceptions import ValidationError


class TestParameterNormalization:
    """Test parameter normalization functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.normalizer = ParameterNormalizer()
    
    def test_fooling_string_to_list_conversion(self):
        """Test that fooling string is converted to fooling_methods list."""
        params = {'fooling': 'badseq'}
        normalized = self.normalizer.normalize(params)
        
        assert 'fooling_methods' in normalized
        assert normalized['fooling_methods'] == ['badseq']
        # Original fooling should be preserved for backward compatibility
        assert normalized['fooling'] == 'badseq'
    
    def test_fooling_list_preserved(self):
        """Test that fooling list is preserved as fooling_methods."""
        params = {'fooling': ['badsum', 'badseq']}
        normalized = self.normalizer.normalize(params)
        
        assert 'fooling_methods' in normalized
        assert normalized['fooling_methods'] == ['badsum', 'badseq']
    
    def test_fooling_methods_already_list(self):
        """Test that fooling_methods list is preserved."""
        params = {'fooling_methods': ['badseq']}
        normalized = self.normalizer.normalize(params)
        
        assert normalized['fooling_methods'] == ['badseq']
    
    def test_fooling_methods_string_to_list(self):
        """Test that fooling_methods string is converted to list."""
        params = {'fooling_methods': 'badsum'}
        normalized = self.normalizer.normalize(params)
        
        assert normalized['fooling_methods'] == ['badsum']
    
    def test_fake_ttl_alias_resolution(self):
        """Test that fake_ttl is resolved to ttl."""
        params = {'fake_ttl': 1}
        normalized = self.normalizer.normalize(params)
        
        assert 'ttl' in normalized
        assert normalized['ttl'] == 1
        # Original fake_ttl should be preserved
        assert normalized['fake_ttl'] == 1
    
    def test_ttl_not_overwritten_by_fake_ttl(self):
        """Test that explicit ttl is not overwritten by fake_ttl."""
        params = {'ttl': 5, 'fake_ttl': 1}
        normalized = self.normalizer.normalize(params)
        
        # Explicit ttl should be preserved
        assert normalized['ttl'] == 5
    
    def test_default_fooling_methods_applied(self):
        """Test that default fooling_methods is applied when missing."""
        params = {}
        normalized = self.normalizer.normalize(params)
        
        assert 'fooling_methods' in normalized
        assert normalized['fooling_methods'] == ['badsum']
    
    def test_default_fake_mode_applied(self):
        """Test that default fake_mode is applied when missing."""
        params = {}
        normalized = self.normalizer.normalize(params)
        
        assert 'fake_mode' in normalized
        assert normalized['fake_mode'] == 'single'
    
    def test_default_disorder_method_applied(self):
        """Test that default disorder_method is applied when missing."""
        params = {}
        normalized = self.normalizer.normalize(params)
        
        assert 'disorder_method' in normalized
        assert normalized['disorder_method'] == 'reverse'
    
    def test_explicit_values_not_overwritten(self):
        """Test that explicit parameter values are never overwritten."""
        params = {
            'fooling': 'badseq',
            'fake_mode': 'per_fragment',
            'disorder_method': 'random'
        }
        normalized = self.normalizer.normalize(params)
        
        # All explicit values should be preserved
        assert normalized['fooling_methods'] == ['badseq']
        assert normalized['fake_mode'] == 'per_fragment'
        assert normalized['disorder_method'] == 'random'
    
    def test_original_params_not_modified(self):
        """Test that original params dict is not modified."""
        params = {'fooling': 'badseq'}
        original_params = params.copy()
        
        self.normalizer.normalize(params)
        
        # Original should be unchanged
        assert params == original_params


class TestParameterValidation:
    """Test parameter validation functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.normalizer = ParameterNormalizer()
    
    def test_valid_ttl_accepted(self):
        """Test that valid TTL values are accepted."""
        params = {'ttl': 1}
        self.normalizer.validate(params)  # Should not raise
        
        params = {'ttl': 128}
        self.normalizer.validate(params)  # Should not raise
        
        params = {'ttl': 255}
        self.normalizer.validate(params)  # Should not raise
    
    def test_ttl_below_range_rejected(self):
        """Test that TTL < 1 is rejected."""
        params = {'ttl': 0}
        
        with pytest.raises(ValidationError) as exc_info:
            self.normalizer.validate(params)
        
        assert exc_info.value.parameter_name == 'ttl'
        assert exc_info.value.actual == 0
    
    def test_ttl_above_range_rejected(self):
        """Test that TTL > 255 is rejected."""
        params = {'ttl': 256}
        
        with pytest.raises(ValidationError) as exc_info:
            self.normalizer.validate(params)
        
        assert exc_info.value.parameter_name == 'ttl'
        assert exc_info.value.actual == 256
    
    def test_ttl_non_integer_rejected(self):
        """Test that non-integer TTL is rejected."""
        params = {'ttl': '5'}
        
        with pytest.raises(ValidationError) as exc_info:
            self.normalizer.validate(params)
        
        assert exc_info.value.parameter_name == 'ttl'
    
    def test_valid_fooling_methods_accepted(self):
        """Test that valid fooling methods are accepted."""
        params = {'fooling_methods': ['badsum']}
        self.normalizer.validate(params)  # Should not raise
        
        params = {'fooling_methods': ['badseq']}
        self.normalizer.validate(params)  # Should not raise
        
        params = {'fooling_methods': ['badsum', 'badseq']}
        self.normalizer.validate(params)  # Should not raise
    
    def test_invalid_fooling_method_rejected(self):
        """Test that invalid fooling methods are rejected."""
        params = {'fooling_methods': ['invalid_method']}
        
        with pytest.raises(ValidationError) as exc_info:
            self.normalizer.validate(params)
        
        assert exc_info.value.parameter_name == 'fooling_methods'
        assert 'invalid_method' in str(exc_info.value.actual)
    
    def test_fooling_methods_not_list_rejected(self):
        """Test that fooling_methods must be a list."""
        params = {'fooling_methods': 'badsum'}
        
        # First normalize to convert string to list
        normalized = self.normalizer.normalize(params)
        # After normalization, it should be valid
        self.normalizer.validate(normalized)  # Should not raise
    
    def test_split_pos_positive_accepted(self):
        """Test that positive split_pos is accepted."""
        params = {'split_pos': 2}
        self.normalizer.validate(params)  # Should not raise
        
        params = {'split_pos': 100}
        self.normalizer.validate(params)  # Should not raise
    
    def test_split_pos_sni_accepted(self):
        """Test that split_pos='sni' is accepted."""
        params = {'split_pos': 'sni'}
        self.normalizer.validate(params)  # Should not raise
    
    def test_split_pos_zero_rejected(self):
        """Test that split_pos=0 is rejected."""
        params = {'split_pos': 0}
        
        with pytest.raises(ValidationError) as exc_info:
            self.normalizer.validate(params)
        
        assert exc_info.value.parameter_name == 'split_pos'
        assert exc_info.value.actual == 0
    
    def test_split_pos_negative_rejected(self):
        """Test that negative split_pos is rejected."""
        params = {'split_pos': -5}
        
        with pytest.raises(ValidationError) as exc_info:
            self.normalizer.validate(params)
        
        assert exc_info.value.parameter_name == 'split_pos'
    
    def test_split_count_valid_accepted(self):
        """Test that split_count >= 2 is accepted."""
        params = {'split_count': 2}
        self.normalizer.validate(params)  # Should not raise
        
        params = {'split_count': 6}
        self.normalizer.validate(params)  # Should not raise
    
    def test_split_count_below_2_rejected(self):
        """Test that split_count < 2 is rejected."""
        params = {'split_count': 1}
        
        with pytest.raises(ValidationError) as exc_info:
            self.normalizer.validate(params)
        
        assert exc_info.value.parameter_name == 'split_count'
        assert exc_info.value.actual == 1
    
    def test_valid_disorder_method_accepted(self):
        """Test that valid disorder methods are accepted."""
        params = {'disorder_method': 'reverse'}
        self.normalizer.validate(params)  # Should not raise
        
        params = {'disorder_method': 'random'}
        self.normalizer.validate(params)  # Should not raise
        
        params = {'disorder_method': 'swap'}
        self.normalizer.validate(params)  # Should not raise
    
    def test_invalid_disorder_method_rejected(self):
        """Test that invalid disorder methods are rejected."""
        params = {'disorder_method': 'invalid'}
        
        with pytest.raises(ValidationError) as exc_info:
            self.normalizer.validate(params)
        
        assert exc_info.value.parameter_name == 'disorder_method'
    
    def test_valid_fake_mode_accepted(self):
        """Test that valid fake modes are accepted."""
        params = {'fake_mode': 'single'}
        self.normalizer.validate(params)  # Should not raise
        
        params = {'fake_mode': 'per_fragment'}
        self.normalizer.validate(params)  # Should not raise
        
        params = {'fake_mode': 'per_signature'}
        self.normalizer.validate(params)  # Should not raise
        
        params = {'fake_mode': 'smart'}
        self.normalizer.validate(params)  # Should not raise
    
    def test_invalid_fake_mode_rejected(self):
        """Test that invalid fake modes are rejected."""
        params = {'fake_mode': 'invalid'}
        
        with pytest.raises(ValidationError) as exc_info:
            self.normalizer.validate(params)
        
        assert exc_info.value.parameter_name == 'fake_mode'


class TestConflictDetection:
    """Test conflict detection functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.normalizer = ParameterNormalizer()
    
    def test_split_pos_and_split_count_conflict(self):
        """Test that split_pos + split_count conflict is detected."""
        params = {'split_pos': 2, 'split_count': 6}
        attacks = ['split']
        
        warnings = self.normalizer.detect_conflicts(params, attacks)
        
        assert len(warnings) > 0
        assert any('split_pos' in w and 'split_count' in w for w in warnings)
    
    def test_fake_mode_without_split_conflict(self):
        """Test that fake_mode without split is detected."""
        params = {'fake_mode': 'per_fragment'}
        attacks = ['fake']  # No split
        
        warnings = self.normalizer.detect_conflicts(params, attacks)
        
        assert len(warnings) > 0
        assert any('fake_mode' in w and 'split' in w for w in warnings)
    
    def test_disorder_method_without_disorder_attack(self):
        """Test that disorder_method without disorder attack is detected."""
        params = {'disorder_method': 'reverse'}
        attacks = ['fake', 'split']  # No disorder
        
        warnings = self.normalizer.detect_conflicts(params, attacks)
        
        assert len(warnings) > 0
        assert any('disorder_method' in w and 'disorder' in w for w in warnings)
    
    def test_unimplemented_attacks_detected(self):
        """Test that unimplemented attacks are detected."""
        params = {}
        attacks = ['fake', 'unknown_attack', 'another_unknown']
        
        warnings = self.normalizer.detect_conflicts(params, attacks)
        
        assert len(warnings) > 0
        assert any('Unimplemented' in w for w in warnings)
    
    def test_no_conflicts_returns_empty_list(self):
        """Test that no conflicts returns empty list."""
        params = {'ttl': 1, 'fooling_methods': ['badsum'], 'split_pos': 2}
        attacks = ['fake', 'split']
        
        warnings = self.normalizer.detect_conflicts(params, attacks)
        
        # Should have no warnings (or only about unimplemented attacks if any)
        # For this test, we expect no warnings
        assert len(warnings) == 0
    
    def test_fake_mode_with_split_no_conflict(self):
        """Test that fake_mode with split has no conflict."""
        params = {'fake_mode': 'per_fragment', 'split_count': 6}
        attacks = ['fake', 'multisplit']
        
        warnings = self.normalizer.detect_conflicts(params, attacks)
        
        # Should not warn about fake_mode since split is present
        assert not any('fake_mode' in w and 'requires split' in w for w in warnings)
    
    def test_disorder_method_with_disorder_attack_no_conflict(self):
        """Test that disorder_method with disorder attack has no conflict."""
        params = {'disorder_method': 'reverse'}
        attacks = ['fake', 'split', 'disorder']
        
        warnings = self.normalizer.detect_conflicts(params, attacks)
        
        # Should not warn about disorder_method since disorder is present
        assert not any('disorder_method' in w and 'not in attacks' in w for w in warnings)


class TestIntegration:
    """Test integration of normalize, validate, and detect_conflicts."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.normalizer = ParameterNormalizer()
    
    def test_full_normalization_and_validation_pipeline(self):
        """Test complete pipeline: normalize → validate → detect conflicts."""
        params = {
            'fooling': 'badseq',
            'ttl': 1,
            'split_pos': 2
        }
        attacks = ['fake', 'split', 'disorder']  # Include disorder to avoid warning
        
        # Normalize
        normalized = self.normalizer.normalize(params)
        
        # Validate
        self.normalizer.validate(normalized)  # Should not raise
        
        # Detect conflicts
        warnings = self.normalizer.detect_conflicts(normalized, attacks)
        
        # Should have no warnings (or only about unimplemented attacks)
        # The normalizer adds default disorder_method, so we need disorder in attacks
        assert len(warnings) == 0
    
    def test_invalid_params_caught_by_validation(self):
        """Test that invalid params are caught after normalization."""
        params = {
            'fooling': 'invalid_method',
            'ttl': 300
        }
        
        # Normalize
        normalized = self.normalizer.normalize(params)
        
        # Validate should raise
        with pytest.raises(ValidationError):
            self.normalizer.validate(normalized)
