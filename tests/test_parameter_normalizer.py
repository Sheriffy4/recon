#!/usr/bin/env python3
"""
Tests for Parameter Normalizer

Tests the single source of truth for parameter normalization and validation.
Addresses issues from CURRENT_BEHAVIOR_ANALYSIS.md.
"""

import pytest
from core.bypass.engine.parameter_normalizer import (
    ParameterNormalizer,
    ValidationResult,
    normalize_attack_params,
)


class TestParameterNormalizer:
    """Test parameter normalization and validation"""

    @pytest.fixture
    def normalizer(self):
        """Create normalizer instance"""
        return ParameterNormalizer()

    def test_alias_resolution_ttl(self, normalizer):
        """Test ttl → fake_ttl alias resolution"""
        params = {"ttl": 3}
        result = normalizer.normalize("fakeddisorder", params)

        assert result.is_valid
        assert "fake_ttl" in result.normalized_params
        assert result.normalized_params["fake_ttl"] == 3
        assert "ttl" not in result.normalized_params
        assert len(result.transformations) == 1
        assert "ttl" in result.transformations[0]

    def test_alias_resolution_fooling(self, normalizer):
        """Test fooling → fooling_methods alias resolution"""
        params = {"fooling": ["badsum", "badseq"]}
        result = normalizer.normalize("fakeddisorder", params)

        assert result.is_valid
        assert "fooling_methods" in result.normalized_params
        assert result.normalized_params["fooling_methods"] == ["badsum", "badseq"]
        assert "fooling" not in result.normalized_params

    def test_alias_resolution_overlap(self, normalizer):
        """Test overlap_size → split_seqovl alias resolution"""
        params = {"overlap_size": 336}
        result = normalizer.normalize("seqovl", params)

        assert result.is_valid
        assert "split_seqovl" in result.normalized_params
        assert result.normalized_params["split_seqovl"] == 336
        assert "overlap_size" not in result.normalized_params

    def test_list_to_value_conversion(self, normalizer):
        """Test split_pos list → first element conversion"""
        params = {"split_pos": [3, 5, 10]}
        result = normalizer.normalize("fakeddisorder", params)

        assert result.is_valid
        assert result.normalized_params["split_pos"] == 3
        assert len(result.warnings) >= 1
        assert "list" in result.warnings[0].lower()

    def test_empty_list_removal(self, normalizer):
        """Test empty split_pos list is removed"""
        params = {"split_pos": []}
        result = normalizer.normalize("fakeddisorder", params)

        assert result.is_valid
        assert "split_pos" not in result.normalized_params
        assert len(result.warnings) >= 1

    def test_fooling_methods_string_to_list(self, normalizer):
        """Test fooling_methods string → list conversion"""
        params = {"fooling_methods": "badsum"}
        result = normalizer.normalize("fakeddisorder", params)

        assert result.is_valid
        assert result.normalized_params["fooling_methods"] == ["badsum"]
        assert len(result.transformations) >= 1

    def test_fooling_methods_none_to_default(self, normalizer):
        """Test fooling_methods None → default list"""
        params = {"fooling_methods": None}
        result = normalizer.normalize("fakeddisorder", params)

        assert result.is_valid
        assert result.normalized_params["fooling_methods"] == ["badsum"]

    def test_special_value_sni(self, normalizer):
        """Test 'sni' special value resolution"""
        params = {"split_pos": "sni"}
        result = normalizer.normalize("fakeddisorder", params, payload_len=100)

        assert result.is_valid
        assert result.normalized_params["split_pos"] == 43
        assert len(result.transformations) >= 1
        assert "sni" in result.transformations[0].lower()

    def test_special_value_cipher(self, normalizer):
        """Test 'cipher' special value resolution"""
        params = {"split_pos": "cipher"}
        result = normalizer.normalize("fakeddisorder", params, payload_len=100)

        assert result.is_valid
        assert result.normalized_params["split_pos"] == 11

    def test_special_value_midsld(self, normalizer):
        """Test 'midsld' special value resolution"""
        params = {"split_pos": "midsld"}
        result = normalizer.normalize("fakeddisorder", params, payload_len=100)

        assert result.is_valid
        assert result.normalized_params["split_pos"] == 50  # 100 // 2

    def test_special_value_exceeds_payload(self, normalizer):
        """Test special value falls back when exceeding payload"""
        params = {"split_pos": "sni"}  # Position 43
        result = normalizer.normalize("fakeddisorder", params, payload_len=20)

        assert result.is_valid
        assert result.normalized_params["split_pos"] == 10  # Falls back to middle
        assert len(result.warnings) >= 1

    def test_special_value_without_payload_len(self, normalizer):
        """Test midsld without payload_len defers resolution"""
        params = {"split_pos": "midsld"}
        result = normalizer.normalize("fakeddisorder", params, payload_len=None)

        assert result.is_valid
        # Should still be 'midsld' or have a warning
        assert len(result.warnings) >= 1

    def test_ttl_validation_valid(self, normalizer):
        """Test valid TTL values"""
        params = {"fake_ttl": 64}
        result = normalizer.normalize("fakeddisorder", params)

        assert result.is_valid
        assert result.normalized_params["fake_ttl"] == 64

    def test_ttl_validation_too_low(self, normalizer):
        """Test TTL too low"""
        params = {"fake_ttl": 0}
        result = normalizer.normalize("fakeddisorder", params)

        assert not result.is_valid
        assert "fake_ttl" in result.error_message
        assert "1 and 255" in result.error_message

    def test_ttl_validation_too_high(self, normalizer):
        """Test TTL too high"""
        params = {"fake_ttl": 300}
        result = normalizer.normalize("fakeddisorder", params)

        assert not result.is_valid
        assert "fake_ttl" in result.error_message

    def test_ttl_string_conversion(self, normalizer):
        """Test TTL string → int conversion"""
        params = {"fake_ttl": "64"}
        result = normalizer.normalize("fakeddisorder", params)

        assert result.is_valid
        assert result.normalized_params["fake_ttl"] == 64
        assert isinstance(result.normalized_params["fake_ttl"], int)

    def test_split_pos_validation_valid(self, normalizer):
        """Test valid split_pos"""
        params = {"split_pos": 10}
        result = normalizer.normalize("fakeddisorder", params, payload_len=100)

        assert result.is_valid
        assert result.normalized_params["split_pos"] == 10

    def test_split_pos_validation_too_low(self, normalizer):
        """Test split_pos too low"""
        params = {"split_pos": 0}
        result = normalizer.normalize("fakeddisorder", params)

        assert not result.is_valid
        assert "split_pos" in result.error_message
        assert ">= 1" in result.error_message

    def test_split_pos_validation_exceeds_payload(self, normalizer):
        """Test split_pos exceeds payload length"""
        params = {"split_pos": 150}
        result = normalizer.normalize("fakeddisorder", params, payload_len=100)

        assert not result.is_valid
        assert "split_pos" in result.error_message
        assert "payload length" in result.error_message

    def test_split_seqovl_validation_valid(self, normalizer):
        """Test valid split_seqovl"""
        params = {"split_seqovl": 336}
        result = normalizer.normalize("seqovl", params, payload_len=1000)

        assert result.is_valid
        assert result.normalized_params["split_seqovl"] == 336

    def test_split_seqovl_validation_negative(self, normalizer):
        """Test negative split_seqovl"""
        params = {"split_seqovl": -10}
        result = normalizer.normalize("seqovl", params)

        assert not result.is_valid
        assert "split_seqovl" in result.error_message

    def test_split_seqovl_validation_exceeds_payload(self, normalizer):
        """Test split_seqovl exceeds payload"""
        params = {"split_seqovl": 500}
        result = normalizer.normalize("seqovl", params, payload_len=100)

        assert not result.is_valid
        assert "split_seqovl" in result.error_message

    def test_positions_validation_valid(self, normalizer):
        """Test valid positions list"""
        params = {"positions": [1, 5, 10, 20]}
        result = normalizer.normalize("multidisorder", params, payload_len=100)

        assert result.is_valid
        assert result.normalized_params["positions"] == [1, 5, 10, 20]

    def test_positions_validation_not_list(self, normalizer):
        """Test positions not a list"""
        params = {"positions": 10}
        result = normalizer.normalize("multidisorder", params)

        assert not result.is_valid
        assert "positions" in result.error_message
        assert "list" in result.error_message

    def test_positions_validation_invalid_element(self, normalizer):
        """Test positions with invalid element"""
        params = {"positions": [1, "invalid", 10]}
        result = normalizer.normalize("multidisorder", params)

        assert not result.is_valid
        assert "positions" in result.error_message

    def test_positions_validation_negative(self, normalizer):
        """Test positions with negative value"""
        params = {"positions": [1, -5, 10]}
        result = normalizer.normalize("multidisorder", params)

        assert not result.is_valid
        assert "positions" in result.error_message

    def test_positions_validation_exceeds_payload(self, normalizer):
        """Test positions exceeding payload"""
        params = {"positions": [1, 5, 150]}
        result = normalizer.normalize("multidisorder", params, payload_len=100)

        assert not result.is_valid
        assert "positions" in result.error_message
        assert "payload length" in result.error_message

    def test_canonical_format_multisplit_split_pos(self, normalizer):
        """Test split_pos → positions for multisplit"""
        params = {"split_pos": 10}
        result = normalizer.normalize("multisplit", params)

        assert result.is_valid
        assert "positions" in result.normalized_params
        assert result.normalized_params["positions"] == [10]
        assert "split_pos" not in result.normalized_params
        assert len(result.transformations) >= 1

    def test_canonical_format_multidisorder_split_pos(self, normalizer):
        """Test split_pos → positions for multidisorder"""
        params = {"split_pos": 5}
        result = normalizer.normalize("multidisorder", params)

        assert result.is_valid
        assert "positions" in result.normalized_params
        assert result.normalized_params["positions"] == [5]

    def test_canonical_format_fakeddisorder_keeps_split_pos(self, normalizer):
        """Test fakeddisorder keeps split_pos (not converted to positions)"""
        params = {"split_pos": 3}
        result = normalizer.normalize("fakeddisorder", params)

        assert result.is_valid
        assert "split_pos" in result.normalized_params
        assert result.normalized_params["split_pos"] == 3
        assert "positions" not in result.normalized_params

    def test_split_count_warning(self, normalizer):
        """Test split_count generates warning (needs payload_len)"""
        params = {"split_count": 5}
        result = normalizer.normalize("multisplit", params)

        assert result.is_valid
        assert len(result.warnings) >= 1
        assert "split_count" in result.warnings[0]

    def test_complex_normalization(self, normalizer):
        """Test complex normalization with multiple transformations"""
        params = {
            "ttl": 3,  # Alias
            "split_pos": [10],  # List to value
            "fooling": "badsum",  # Alias + string to list
        }
        result = normalizer.normalize("fakeddisorder", params, payload_len=100)

        assert result.is_valid
        assert "fake_ttl" in result.normalized_params
        assert result.normalized_params["fake_ttl"] == 3
        assert result.normalized_params["split_pos"] == 10
        assert result.normalized_params["fooling_methods"] == ["badsum"]
        assert len(result.transformations) >= 3

    def test_validation_result_add_transformation(self):
        """Test ValidationResult.add_transformation"""
        result = ValidationResult(is_valid=True, normalized_params={})
        result.add_transformation(
            "split_pos", [3, 5], 3, "Converted list to first element"
        )

        assert len(result.transformations) == 1
        assert len(result.warnings) == 1
        assert "split_pos" in result.transformations[0]
        assert "[3, 5]" in result.transformations[0]
        assert "3" in result.transformations[0]


class TestConvenienceFunction:
    """Test convenience function"""

    def test_normalize_attack_params(self):
        """Test convenience function works"""
        params = {"ttl": 3, "split_pos": "sni"}
        result = normalize_attack_params("fakeddisorder", params, payload_len=100)

        assert result.is_valid
        assert "fake_ttl" in result.normalized_params
        assert result.normalized_params["split_pos"] == 43


class TestStrictMode:
    """Test strict mode behavior"""

    def test_strict_mode_list_split_pos_error(self):
        """Test strict mode rejects list split_pos"""
        normalizer = ParameterNormalizer(strict_mode=True)
        params = {"split_pos": [3, 5]}
        result = normalizer.normalize("fakeddisorder", params)

        assert not result.is_valid
        assert "Ambiguous parameter" in result.error_message
        assert "split_pos" in result.error_message

    def test_non_strict_mode_list_split_pos_warning(self):
        """Test non-strict mode converts list split_pos with warning"""
        normalizer = ParameterNormalizer(strict_mode=False)
        params = {"split_pos": [3, 5]}
        result = normalizer.normalize("fakeddisorder", params)

        assert result.is_valid
        assert result.normalized_params["split_pos"] == 3
        assert len(result.warnings) >= 1

    def test_strict_mode_convenience_function(self):
        """Test strict mode via convenience function"""
        params = {"split_pos": [10]}
        result = normalize_attack_params("fakeddisorder", params, strict_mode=True)

        assert not result.is_valid
        assert "Ambiguous" in result.error_message


class TestAllAttackTypes:
    """Test normalization for all attack types"""

    @pytest.fixture
    def normalizer(self):
        return ParameterNormalizer()

    def test_disorder2_ack_first_default(self, normalizer):
        """Test disorder2 gets ack_first=True by default"""
        params = {"split_pos": 5}
        result = normalizer.normalize("disorder2", params)

        assert result.is_valid
        assert result.normalized_params["ack_first"] is True
        assert len(result.transformations) >= 1

    def test_wssize_limit_window_size_default(self, normalizer):
        """Test wssize_limit gets window_size=1 by default"""
        params = {}
        result = normalizer.normalize("wssize_limit", params)

        assert result.is_valid
        assert result.normalized_params["window_size"] == 1
        assert len(result.transformations) >= 1

    def test_tlsrec_split_split_pos_default(self, normalizer):
        """Test tlsrec_split gets split_pos=5 by default"""
        params = {}
        result = normalizer.normalize("tlsrec_split", params)

        assert result.is_valid
        assert result.normalized_params["split_pos"] == 5
        assert len(result.transformations) >= 1

    def test_fake_attack_fake_ttl_default(self, normalizer):
        """Test fake attacks get fake_ttl=3 by default"""
        params = {}
        result = normalizer.normalize("fake", params)

        assert result.is_valid
        assert result.normalized_params["fake_ttl"] == 3
        assert len(result.transformations) >= 1

    def test_attack_type_aliases(self, normalizer):
        """Test attack type alias normalization"""
        aliases_to_test = [
            ("fake_disorder", "fakeddisorder"),
            ("fakedisorder", "fakeddisorder"),
            ("multi_split", "multisplit"),
            ("seq_overlap", "seqovl"),
            ("simple_disorder", "disorder"),
        ]

        for alias, canonical in aliases_to_test:
            params = {"split_pos": 5}
            result_alias = normalizer.normalize(alias, params)
            result_canonical = normalizer.normalize(canonical, params)

            # Should produce similar results (accounting for attack-specific defaults)
            assert result_alias.is_valid == result_canonical.is_valid

    def test_parameter_aliases_extended(self, normalizer):
        """Test extended parameter aliases"""
        # Test window_size aliases
        params = {"window": 10}
        result = normalizer.normalize("wssize_limit", params)
        assert result.is_valid
        assert result.normalized_params["window_size"] == 10

        # Test ack_first alias
        params = {"ack": True}
        result = normalizer.normalize("disorder2", params)
        assert result.is_valid
        assert result.normalized_params["ack_first"] is True

    def test_window_size_validation(self, normalizer):
        """Test window_size parameter validation"""
        # Valid window_size
        params = {"window_size": 1024}
        result = normalizer.normalize("wssize_limit", params)
        assert result.is_valid

        # Invalid window_size (too low)
        params = {"window_size": 0}
        result = normalizer.normalize("wssize_limit", params)
        assert not result.is_valid
        assert "window_size" in result.error_message

        # Invalid window_size (too high)
        params = {"window_size": 100000}
        result = normalizer.normalize("wssize_limit", params)
        assert not result.is_valid
        assert "window_size" in result.error_message

    def test_ack_first_boolean_conversion(self, normalizer):
        """Test ack_first boolean conversion"""
        test_cases = [
            ("true", True),
            ("false", False),
            ("1", True),
            ("0", False),
            ("yes", True),
            ("no", False),
            (1, True),
            (0, False),
        ]

        for input_val, expected in test_cases:
            params = {"ack_first": input_val}
            result = normalizer.normalize("disorder2", params)
            assert result.is_valid
            assert result.normalized_params["ack_first"] == expected

    def test_fooling_methods_extended_validation(self, normalizer):
        """Test extended fooling methods validation"""
        # Valid extended methods
        params = {"fooling_methods": ["badsum", "fakesni"]}
        result = normalizer.normalize("fakeddisorder", params)
        assert result.is_valid

        # Invalid method
        params = {"fooling_methods": ["invalid_method"]}
        result = normalizer.normalize("fakeddisorder", params)
        assert not result.is_valid
        assert "Invalid fooling method" in result.error_message


class TestEdgeCases:
    """Test edge cases and error handling"""

    @pytest.fixture
    def normalizer(self):
        return ParameterNormalizer()

    def test_empty_params(self, normalizer):
        """Test empty parameters"""
        result = normalizer.normalize("fakeddisorder", {})

        assert result.is_valid
        # Should have default fake_ttl added
        assert "fake_ttl" in result.normalized_params
        assert result.normalized_params["fake_ttl"] == 3

    def test_unknown_special_value(self, normalizer):
        """Test unknown special value"""
        params = {"split_pos": "unknown_value"}
        result = normalizer.normalize("fakeddisorder", params)

        assert result.is_valid  # Doesn't fail, just warns
        assert len(result.warnings) >= 1
        assert "unknown" in result.warnings[0].lower()

    def test_invalid_type_ttl(self, normalizer):
        """Test invalid type for TTL"""
        params = {"fake_ttl": "not_a_number"}
        result = normalizer.normalize("fakeddisorder", params)

        assert not result.is_valid
        assert "fake_ttl" in result.error_message

    def test_multiple_errors(self, normalizer):
        """Test multiple validation errors"""
        params = {
            "fake_ttl": 0,  # Too low
            "split_pos": -1,  # Too low
            "split_seqovl": -10,  # Negative
        }
        result = normalizer.normalize("fakeddisorder", params)

        assert not result.is_valid
        assert "fake_ttl" in result.error_message
        # Should contain multiple errors
        assert ";" in result.error_message or len(result.error_message) > 50


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
