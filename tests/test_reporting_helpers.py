#!/usr/bin/env python3
"""
Unit tests for reporting helper functions.
"""

import pytest
from datetime import datetime, timedelta
from core.integration.reporting_models import AdvancedAttackReport
from core.integration.reporting_helpers import (
    calculate_dpi_analysis,
    calculate_attack_analysis,
    filter_recent_reports,
    calculate_performance_summary,
)


class TestCalculateDpiAnalysis:
    """Tests for calculate_dpi_analysis function."""

    def test_with_multiple_dpi_types(self):
        """Test DPI analysis with multiple types."""
        reports = [
            AdvancedAttackReport(
                attack_name="test",
                target_domain="test.com",
                dpi_type="type_a",
                execution_time_ms=100,
                success=True,
                effectiveness_score=0.8,
                timestamp=datetime.now(),
                performance_metrics={},
                ml_insights={},
                recommendations=[],
            ),
            AdvancedAttackReport(
                attack_name="test",
                target_domain="test.com",
                dpi_type="type_a",
                execution_time_ms=100,
                success=False,
                effectiveness_score=0.4,
                timestamp=datetime.now(),
                performance_metrics={},
                ml_insights={},
                recommendations=[],
            ),
            AdvancedAttackReport(
                attack_name="test",
                target_domain="test.com",
                dpi_type="type_b",
                execution_time_ms=100,
                success=True,
                effectiveness_score=0.9,
                timestamp=datetime.now(),
                performance_metrics={},
                ml_insights={},
                recommendations=[],
            ),
        ]

        analysis = calculate_dpi_analysis(reports)

        assert "type_a" in analysis
        assert "type_b" in analysis
        assert analysis["type_a"]["total"] == 2
        assert analysis["type_a"]["successful"] == 1
        assert analysis["type_b"]["total"] == 1


class TestCalculateAttackAnalysis:
    """Tests for calculate_attack_analysis function."""

    def test_with_multiple_attacks(self):
        """Test attack analysis with multiple attack types."""
        reports = [
            AdvancedAttackReport(
                attack_name="attack1",
                target_domain="test.com",
                dpi_type="unknown",
                execution_time_ms=100,
                success=True,
                effectiveness_score=0.8,
                timestamp=datetime.now(),
                performance_metrics={},
                ml_insights={},
                recommendations=[],
            ),
            AdvancedAttackReport(
                attack_name="attack1",
                target_domain="test.com",
                dpi_type="unknown",
                execution_time_ms=100,
                success=True,
                effectiveness_score=0.9,
                timestamp=datetime.now(),
                performance_metrics={},
                ml_insights={},
                recommendations=[],
            ),
            AdvancedAttackReport(
                attack_name="attack2",
                target_domain="test.com",
                dpi_type="unknown",
                execution_time_ms=100,
                success=False,
                effectiveness_score=0.3,
                timestamp=datetime.now(),
                performance_metrics={},
                ml_insights={},
                recommendations=[],
            ),
        ]

        analysis = calculate_attack_analysis(reports)

        assert "attack1" in analysis
        assert "attack2" in analysis
        assert analysis["attack1"]["executions"] == 2
        assert analysis["attack1"]["successes"] == 2
        assert analysis["attack2"]["executions"] == 1


class TestFilterRecentReports:
    """Tests for filter_recent_reports function."""

    def test_filter_24_hours(self):
        """Test filtering reports from last 24 hours."""
        now = datetime.now()
        reports = [
            AdvancedAttackReport(
                attack_name="test",
                target_domain="test.com",
                dpi_type="unknown",
                execution_time_ms=100,
                success=True,
                effectiveness_score=0.8,
                timestamp=now - timedelta(hours=12),
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
                effectiveness_score=0.8,
                timestamp=now - timedelta(hours=48),
                performance_metrics={},
                ml_insights={},
                recommendations=[],
            ),
        ]

        recent = filter_recent_reports(reports, hours=24)

        assert len(recent) == 1
        assert recent[0].timestamp > now - timedelta(hours=24)


class TestCalculatePerformanceSummary:
    """Tests for calculate_performance_summary function."""

    def test_with_reports(self):
        """Test calculating performance summary."""
        reports = [
            AdvancedAttackReport(
                attack_name="attack1",
                target_domain="target1.com",
                dpi_type="unknown",
                execution_time_ms=100,
                success=True,
                effectiveness_score=0.8,
                timestamp=datetime.now(),
                performance_metrics={},
                ml_insights={},
                recommendations=[],
            ),
            AdvancedAttackReport(
                attack_name="attack2",
                target_domain="target2.com",
                dpi_type="unknown",
                execution_time_ms=100,
                success=False,
                effectiveness_score=0.4,
                timestamp=datetime.now(),
                performance_metrics={},
                ml_insights={},
                recommendations=[],
            ),
        ]

        summary = calculate_performance_summary(reports)

        assert summary["total_attacks_24h"] == 2
        assert summary["success_rate_24h"] == 50.0
        assert summary["unique_targets_24h"] == 2
        assert summary["unique_attacks_used"] == 2

    def test_with_empty_reports(self):
        """Test with empty reports list."""
        summary = calculate_performance_summary([])

        assert summary["total_attacks_24h"] == 0
        assert summary["success_rate_24h"] == 0
