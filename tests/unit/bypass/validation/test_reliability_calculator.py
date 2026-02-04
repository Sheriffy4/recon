#!/usr/bin/env python3
"""
Unit tests for reliability_calculator module.

Tests all pure calculation functions to ensure correct scoring and classification.
"""

import pytest
from core.bypass.validation.reliability_calculator import (
    calculate_reliability_score,
    detect_false_positive_in_results,
    determine_accessibility_status,
    calculate_effectiveness_score,
    detect_false_positives,
    calculate_consistency_score,
    calculate_performance_score,
    determine_reliability_level,
    generate_strategy_recommendation,
)
from core.bypass.validation.types import (
    ValidationMethod,
    ValidationResult,
    AccessibilityResult,
    AccessibilityStatus,
    ReliabilityLevel,
)


class TestCalculateReliabilityScore:
    """Tests for calculate_reliability_score function."""

    def test_empty_results(self):
        """Test with empty results list."""
        score = calculate_reliability_score([], max_response_time=10.0)
        assert score == 0.0

    def test_all_successful(self):
        """Test with all successful validations."""
        results = [
            ValidationResult(
                method=ValidationMethod.HTTP_RESPONSE,
                success=True,
                response_time=1.0,
            ),
            ValidationResult(
                method=ValidationMethod.CONTENT_CHECK,
                success=True,
                response_time=1.5,
            ),
        ]
        score = calculate_reliability_score(results, max_response_time=10.0)
        assert 0.8 < score <= 1.0  # Should be high

    def test_all_failed(self):
        """Test with all failed validations."""
        results = [
            ValidationResult(
                method=ValidationMethod.HTTP_RESPONSE,
                success=False,
                response_time=10.0,
            ),
            ValidationResult(
                method=ValidationMethod.CONTENT_CHECK,
                success=False,
                response_time=10.0,
            ),
        ]
        score = calculate_reliability_score(results, max_response_time=10.0)
        assert score == 0.0

    def test_slow_response_penalty(self):
        """Test that slow responses reduce score."""
        fast_result = ValidationResult(
            method=ValidationMethod.HTTP_RESPONSE,
            success=True,
            response_time=1.0,
        )
        slow_result = ValidationResult(
            method=ValidationMethod.HTTP_RESPONSE,
            success=True,
            response_time=9.0,
        )

        fast_score = calculate_reliability_score([fast_result], max_response_time=10.0)
        slow_score = calculate_reliability_score([slow_result], max_response_time=10.0)

        assert fast_score > slow_score


class TestDetermineReliabilityLevel:
    """Tests for determine_reliability_level function."""

    def test_excellent_level(self):
        """Test excellent reliability classification."""
        level = determine_reliability_level(
            effectiveness_score=0.95,
            consistency_score=0.95,
            false_positive_rate=0.0,
        )
        assert level == ReliabilityLevel.EXCELLENT

    def test_unreliable_level(self):
        """Test unreliable classification."""
        level = determine_reliability_level(
            effectiveness_score=0.1,
            consistency_score=0.1,
            false_positive_rate=0.9,
        )
        assert level == ReliabilityLevel.UNRELIABLE

    def test_moderate_level(self):
        """Test moderate reliability classification."""
        level = determine_reliability_level(
            effectiveness_score=0.6,
            consistency_score=0.5,
            false_positive_rate=0.3,
        )
        assert level == ReliabilityLevel.MODERATE


class TestGenerateStrategyRecommendation:
    """Tests for generate_strategy_recommendation function."""

    def test_excellent_with_good_performance(self):
        """Test recommendation for excellent reliability with good performance."""
        recommendation = generate_strategy_recommendation(
            reliability_level=ReliabilityLevel.EXCELLENT,
            false_positive_rate=0.05,
            consistency_score=0.9,
            performance_score=0.85,
        )
        assert "Highly recommended" in recommendation
        assert "excellent" in recommendation.lower()

    def test_unreliable_recommendation(self):
        """Test recommendation for unreliable strategy."""
        recommendation = generate_strategy_recommendation(
            reliability_level=ReliabilityLevel.UNRELIABLE,
            false_positive_rate=0.8,
            consistency_score=0.3,
            performance_score=0.2,
        )
        assert "Avoid" in recommendation or "unreliable" in recommendation.lower()

    def test_moderate_with_consistency(self):
        """Test recommendation for moderate reliability with good consistency."""
        recommendation = generate_strategy_recommendation(
            reliability_level=ReliabilityLevel.MODERATE,
            false_positive_rate=0.2,
            consistency_score=0.75,
            performance_score=0.6,
        )
        assert "Limited use" in recommendation or "moderate" in recommendation.lower()


class TestCalculateConsistencyScore:
    """Tests for calculate_consistency_score function."""

    def test_single_result_perfect_consistency(self):
        """Test that single result has perfect consistency."""
        results = [
            AccessibilityResult(
                domain="test.com",
                port=443,
                status=AccessibilityStatus.ACCESSIBLE,
                validation_results=[],
                reliability_score=0.9,
                false_positive_detected=False,
                bypass_effectiveness=0.9,
                total_tests=1,
                successful_tests=1,
                average_response_time=1.0,
            )
        ]
        score = calculate_consistency_score(results)
        assert score == 1.0

    def test_identical_results_high_consistency(self):
        """Test that identical results have high consistency."""
        results = [
            AccessibilityResult(
                domain="test.com",
                port=443,
                status=AccessibilityStatus.ACCESSIBLE,
                validation_results=[],
                reliability_score=0.9,
                false_positive_detected=False,
                bypass_effectiveness=0.9,
                total_tests=1,
                successful_tests=1,
                average_response_time=1.0,
            )
            for _ in range(3)
        ]
        score = calculate_consistency_score(results)
        assert score > 0.95

    def test_varying_results_lower_consistency(self):
        """Test that varying results have lower consistency."""
        results = [
            AccessibilityResult(
                domain="test.com",
                port=443,
                status=AccessibilityStatus.ACCESSIBLE,
                validation_results=[],
                reliability_score=0.9,
                false_positive_detected=False,
                bypass_effectiveness=0.9,
                total_tests=1,
                successful_tests=1,
                average_response_time=1.0,
            ),
            AccessibilityResult(
                domain="test.com",
                port=443,
                status=AccessibilityStatus.BLOCKED,
                validation_results=[],
                reliability_score=0.3,
                false_positive_detected=True,
                bypass_effectiveness=0.2,
                total_tests=1,
                successful_tests=0,
                average_response_time=5.0,
            ),
        ]
        score = calculate_consistency_score(results)
        assert score < 0.7


class TestCalculatePerformanceScore:
    """Tests for calculate_performance_score function."""

    def test_empty_results(self):
        """Test with empty results."""
        score = calculate_performance_score([], max_acceptable_time=10.0)
        assert score == 0.0

    def test_excellent_performance(self):
        """Test with excellent response times."""
        results = [
            AccessibilityResult(
                domain="test.com",
                port=443,
                status=AccessibilityStatus.ACCESSIBLE,
                validation_results=[],
                reliability_score=0.9,
                false_positive_detected=False,
                bypass_effectiveness=0.9,
                total_tests=1,
                successful_tests=1,
                average_response_time=0.5,
            )
        ]
        score = calculate_performance_score(results, max_acceptable_time=10.0)
        assert score == 1.0

    def test_poor_performance(self):
        """Test with poor response times."""
        results = [
            AccessibilityResult(
                domain="test.com",
                port=443,
                status=AccessibilityStatus.ACCESSIBLE,
                validation_results=[],
                reliability_score=0.9,
                false_positive_detected=False,
                bypass_effectiveness=0.9,
                total_tests=1,
                successful_tests=1,
                average_response_time=15.0,
            )
        ]
        score = calculate_performance_score(results, max_acceptable_time=10.0)
        assert score < 0.5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
