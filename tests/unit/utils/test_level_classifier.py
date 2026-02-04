#!/usr/bin/env python3
"""
Unit tests for level_classifier utility.

Tests generic threshold-based classification functionality.
"""

import pytest
from enum import Enum
from core.utils.level_classifier import classify_by_thresholds, create_threshold_classifier


class TestLevel(Enum):
    """Test enum for classification."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TestClassifyByThresholds:
    """Tests for classify_by_thresholds function."""

    def test_descending_classification_high(self):
        """Test descending classification for high score."""
        thresholds = [(0.8, TestLevel.HIGH), (0.5, TestLevel.MEDIUM)]
        result = classify_by_thresholds(0.9, thresholds, TestLevel.LOW, descending=True)
        assert result == TestLevel.HIGH

    def test_descending_classification_medium(self):
        """Test descending classification for medium score."""
        thresholds = [(0.8, TestLevel.HIGH), (0.5, TestLevel.MEDIUM)]
        result = classify_by_thresholds(0.6, thresholds, TestLevel.LOW, descending=True)
        assert result == TestLevel.MEDIUM

    def test_descending_classification_default(self):
        """Test descending classification returns default for low score."""
        thresholds = [(0.8, TestLevel.HIGH), (0.5, TestLevel.MEDIUM)]
        result = classify_by_thresholds(0.3, thresholds, TestLevel.LOW, descending=True)
        assert result == TestLevel.LOW

    def test_ascending_classification(self):
        """Test ascending classification."""
        thresholds = [(0.3, TestLevel.LOW), (0.7, TestLevel.MEDIUM)]
        result = classify_by_thresholds(0.5, thresholds, TestLevel.HIGH, descending=False)
        assert result == TestLevel.MEDIUM

    def test_exact_threshold_match(self):
        """Test classification with exact threshold match."""
        thresholds = [(0.8, TestLevel.HIGH), (0.5, TestLevel.MEDIUM)]
        result = classify_by_thresholds(0.8, thresholds, TestLevel.LOW, descending=True)
        assert result == TestLevel.HIGH

    def test_empty_thresholds(self):
        """Test with empty thresholds returns default."""
        result = classify_by_thresholds(0.5, [], TestLevel.LOW, descending=True)
        assert result == TestLevel.LOW


class TestCreateThresholdClassifier:
    """Tests for create_threshold_classifier function."""

    def test_classifier_creation(self):
        """Test creating a reusable classifier."""
        thresholds = [(0.8, TestLevel.HIGH), (0.5, TestLevel.MEDIUM)]
        classifier = create_threshold_classifier(thresholds, TestLevel.LOW, descending=True)

        assert classifier(0.9) == TestLevel.HIGH
        assert classifier(0.6) == TestLevel.MEDIUM
        assert classifier(0.3) == TestLevel.LOW

    def test_classifier_reusability(self):
        """Test that classifier can be reused multiple times."""
        thresholds = [(0.8, TestLevel.HIGH), (0.5, TestLevel.MEDIUM)]
        classifier = create_threshold_classifier(thresholds, TestLevel.LOW, descending=True)

        # Use classifier multiple times
        results = [classifier(score) for score in [0.9, 0.7, 0.4, 0.85, 0.2]]

        assert results[0] == TestLevel.HIGH
        assert results[1] == TestLevel.MEDIUM
        assert results[2] == TestLevel.LOW
        assert results[3] == TestLevel.HIGH
        assert results[4] == TestLevel.LOW


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
