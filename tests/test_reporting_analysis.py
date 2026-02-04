#!/usr/bin/env python3
"""
Unit tests for reporting analysis functions.
"""

import pytest
from datetime import datetime, timedelta
from core.integration.reporting_models import AdvancedAttackReport
from core.integration.reporting_analysis import (
    analyze_performance_trends,
    analyze_attack_trend,
    calculate_average_effectiveness,
)


class TestAnalyzePerformanceTrends:
    """Tests for analyze_performance_trends function."""

    def test_with_valid_data(self):
        """Test analyzing performance trends with valid data."""
        performance_data = {
            "attack_metrics": [
                {
                    "timestamp": datetime.now().isoformat(),
                    "success": True,
                    "effectiveness_score": 0.85,
                },
                {
                    "timestamp": datetime.now().isoformat(),
                    "success": False,
                    "effectiveness_score": 0.45,
                },
            ]
        }

        trends = analyze_performance_trends(performance_data)

        assert isinstance(trends, dict)
        assert len(trends) > 0

    def test_with_empty_data(self):
        """Test with empty performance data."""
        performance_data = {"attack_metrics": []}

        trends = analyze_performance_trends(performance_data)

        assert trends == {"message": "No performance data available"}

    def test_with_missing_metrics(self):
        """Test with missing attack_metrics key."""
        performance_data = {}

        trends = analyze_performance_trends(performance_data)

        assert trends == {"message": "No performance data available"}


class TestAnalyzeAttackTrend:
    """Tests for analyze_attack_trend function."""

    def test_insufficient_data(self):
        """Test with insufficient reports."""
        reports = [
            AdvancedAttackReport(
                attack_name="test",
                target_domain="test.com",
                dpi_type="unknown",
                execution_time_ms=100,
                success=True,
                effectiveness_score=0.8,
                timestamp=datetime.now(),
                performance_metrics={},
                ml_insights={},
                recommendations=[],
            )
        ]

        trend = analyze_attack_trend(reports)

        assert trend["trend"] == "insufficient_data"

    def test_improving_trend(self):
        """Test detecting improving trend."""
        base_time = datetime.now()
        reports = [
            AdvancedAttackReport(
                attack_name="test",
                target_domain="test.com",
                dpi_type="unknown",
                execution_time_ms=100,
                success=False,
                effectiveness_score=0.3,
                timestamp=base_time - timedelta(hours=3),
                performance_metrics={},
                ml_insights={},
                recommendations=[],
            ),
            AdvancedAttackReport(
                attack_name="test",
                target_domain="test.com",
                dpi_type="unknown",
                execution_time_ms=100,
                success=True,
                effectiveness_score=0.6,
                timestamp=base_time - timedelta(hours=2),
                performance_metrics={},
                ml_insights={},
                recommendations=[],
            ),
            AdvancedAttackReport(
                attack_name="test",
                target_domain="test.com",
                dpi_type="unknown",
                execution_time_ms=100,
                success=True,
                effectiveness_score=0.9,
                timestamp=base_time - timedelta(hours=1),
                performance_metrics={},
                ml_insights={},
                recommendations=[],
            ),
        ]

        trend = analyze_attack_trend(reports)

        assert trend["trend"] in ["improving", "stable"]


class TestCalculateAverageEffectiveness:
    """Tests for calculate_average_effectiveness function."""

    def test_with_valid_data(self):
        """Test calculating average with valid data."""
        performance_data = {
            "attack_metrics": [
                {"effectiveness_score": 0.8},
                {"effectiveness_score": 0.6},
                {"effectiveness_score": 0.9},
            ]
        }

        avg = calculate_average_effectiveness(performance_data)

        assert avg == pytest.approx(0.7667, rel=0.01)

    def test_with_empty_data(self):
        """Test with empty data."""
        performance_data = {"attack_metrics": []}

        avg = calculate_average_effectiveness(performance_data)

        assert avg == 0.0

    def test_with_missing_key(self):
        """Test with missing attack_metrics key."""
        performance_data = {}

        avg = calculate_average_effectiveness(performance_data)

        assert avg == 0.0
