"""
Unit tests for helper methods in primitives.py

Tests the new helper methods extracted during refactoring:
- _validate_promotion_inputs
- _validate_performance_data
- _validate_handler_signature
- _log_promotion_success
"""

import logging
import pytest
from unittest.mock import Mock, MagicMock
from core.bypass.techniques.primitives import BypassTechniques


class TestValidatePromotionInputs:
    """Tests for _validate_promotion_inputs helper method."""

    def test_valid_inputs(self):
        """Test validation with all valid inputs."""
        log = logging.getLogger("test")
        handler = lambda x: x
        result = BypassTechniques._validate_promotion_inputs(
            "fakeddisorder", handler, "Performance improvement", log
        )
        assert result is True

    def test_invalid_attack_name_empty(self):
        """Test validation fails with empty attack name."""
        log = logging.getLogger("test")
        handler = lambda x: x
        result = BypassTechniques._validate_promotion_inputs("", handler, "reason", log)
        assert result is False

    def test_invalid_attack_name_none(self):
        """Test validation fails with None attack name."""
        log = logging.getLogger("test")
        handler = lambda x: x
        result = BypassTechniques._validate_promotion_inputs(None, handler, "reason", log)
        assert result is False

    def test_invalid_handler_not_callable(self):
        """Test validation fails with non-callable handler."""
        log = logging.getLogger("test")
        result = BypassTechniques._validate_promotion_inputs(
            "fakeddisorder", "not_callable", "reason", log
        )
        assert result is False

    def test_invalid_reason_empty(self):
        """Test validation fails with empty reason."""
        log = logging.getLogger("test")
        handler = lambda x: x
        result = BypassTechniques._validate_promotion_inputs("fakeddisorder", handler, "", log)
        assert result is False

    def test_invalid_reason_none(self):
        """Test validation fails with None reason."""
        log = logging.getLogger("test")
        handler = lambda x: x
        result = BypassTechniques._validate_promotion_inputs("fakeddisorder", handler, None, log)
        assert result is False


class TestValidatePerformanceData:
    """Tests for _validate_performance_data helper method."""

    def test_valid_performance_data(self):
        """Test validation with complete performance data."""
        log = logging.getLogger("test")
        data = {
            "improvement_percent": 15.5,
            "test_cases": 1000,
            "success_rate": 0.95,
        }
        result = BypassTechniques._validate_performance_data(data, log)
        assert result == data

    def test_none_performance_data(self):
        """Test validation with None returns empty dict."""
        log = logging.getLogger("test")
        result = BypassTechniques._validate_performance_data(None, log)
        assert result == {}

    def test_empty_performance_data(self):
        """Test validation with empty dict."""
        log = logging.getLogger("test")
        result = BypassTechniques._validate_performance_data({}, log)
        assert result == {}

    def test_invalid_type_performance_data(self):
        """Test validation with non-dict type returns empty dict."""
        log = logging.getLogger("test")
        result = BypassTechniques._validate_performance_data("invalid", log)
        assert result == {}

    def test_partial_performance_data(self):
        """Test validation with partial data (missing recommended keys)."""
        log = logging.getLogger("test")
        data = {"improvement_percent": 10.0}
        result = BypassTechniques._validate_performance_data(data, log)
        assert result == data


class TestValidateHandlerSignature:
    """Tests for _validate_handler_signature helper method."""

    def test_valid_handler_with_params(self):
        """Test validation with handler that has parameters."""
        log = logging.getLogger("test")

        def handler(payload, split_pos, ttl):
            return []

        # Should not raise exception
        BypassTechniques._validate_handler_signature(handler, log)

    def test_valid_handler_no_params(self):
        """Test validation with handler that has no parameters."""
        log = logging.getLogger("test")

        def handler():
            return []

        # Should not raise exception (but may log warning)
        BypassTechniques._validate_handler_signature(handler, log)

    def test_lambda_handler(self):
        """Test validation with lambda handler."""
        log = logging.getLogger("test")
        handler = lambda x: x
        # Should not raise exception
        BypassTechniques._validate_handler_signature(handler, log)

    def test_builtin_handler(self):
        """Test validation with builtin function."""
        log = logging.getLogger("test")
        # Should handle gracefully even if inspection fails
        BypassTechniques._validate_handler_signature(len, log)


class TestLogPromotionSuccess:
    """Tests for _log_promotion_success helper method."""

    def test_log_with_full_performance_data(self, caplog):
        """Test logging with complete performance data."""
        log = logging.getLogger("test")
        caplog.set_level(logging.INFO)

        performance_data = {
            "improvement_percent": 15.5,
            "test_cases": 1000,
            "success_rate": 0.95,
        }

        BypassTechniques._log_promotion_success("fakeddisorder", "Better performance", performance_data, log)

        # Check that success message was logged
        assert "Successfully promoted 'fakeddisorder'" in caplog.text
        assert "Better performance" in caplog.text

    def test_log_with_empty_performance_data(self, caplog):
        """Test logging with no performance data."""
        log = logging.getLogger("test")
        caplog.set_level(logging.INFO)

        BypassTechniques._log_promotion_success("fakeddisorder", "Refactored", {}, log)

        # Check that success message was logged
        assert "Successfully promoted 'fakeddisorder'" in caplog.text
        assert "Refactored" in caplog.text

    def test_log_with_partial_performance_data(self, caplog):
        """Test logging with partial performance data."""
        log = logging.getLogger("test")
        caplog.set_level(logging.INFO)

        performance_data = {"improvement_percent": 10.0}

        BypassTechniques._log_promotion_success("seqovl", "Optimized", performance_data, log)

        # Check that success message was logged
        assert "Successfully promoted 'seqovl'" in caplog.text


class TestHelperMethodsIntegration:
    """Integration tests for helper methods working together."""

    def test_promotion_workflow_valid(self):
        """Test complete promotion workflow with valid inputs."""
        log = logging.getLogger("test")

        # Step 1: Validate inputs
        handler = lambda payload, split_pos: []
        inputs_valid = BypassTechniques._validate_promotion_inputs(
            "fakeddisorder", handler, "Performance improvement", log
        )
        assert inputs_valid is True

        # Step 2: Validate performance data
        perf_data = {"improvement_percent": 20.0, "test_cases": 500}
        validated_perf = BypassTechniques._validate_performance_data(perf_data, log)
        assert validated_perf == perf_data

        # Step 3: Validate handler signature
        BypassTechniques._validate_handler_signature(handler, log)

        # Step 4: Log success (would happen after actual promotion)
        BypassTechniques._log_promotion_success("fakeddisorder", "Performance improvement", validated_perf, log)

    def test_promotion_workflow_invalid_inputs(self):
        """Test promotion workflow fails early with invalid inputs."""
        log = logging.getLogger("test")

        # Invalid handler (not callable)
        inputs_valid = BypassTechniques._validate_promotion_inputs(
            "fakeddisorder", "not_callable", "reason", log
        )
        assert inputs_valid is False

        # Should not proceed to other steps if inputs invalid


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
