#!/usr/bin/env python3
"""
Unit tests for reporting models.
"""

import pytest
from datetime import datetime
from core.integration.reporting_models import (
    AdvancedAttackReport,
    SystemPerformanceReport,
)


class TestAdvancedAttackReport:
    """Tests for AdvancedAttackReport model."""

    def test_create_report(self):
        """Test creating a basic attack report."""
        report = AdvancedAttackReport(
            attack_name="http_fragmentation",
            target_domain="example.com",
            dpi_type="deep_packet_inspection",
            execution_time_ms=1250.5,
            success=True,
            effectiveness_score=0.85,
            timestamp=datetime.now(),
            performance_metrics={"cpu": 45.2},
            ml_insights={"prediction": "accurate"},
            recommendations=["Optimize parameters"],
        )

        assert report.attack_name == "http_fragmentation"
        assert report.target_domain == "example.com"
        assert report.success is True
        assert report.effectiveness_score == 0.85

    def test_report_with_minimal_data(self):
        """Test creating report with minimal required data."""
        report = AdvancedAttackReport(
            attack_name="test_attack",
            target_domain="test.com",
            dpi_type="unknown",
            execution_time_ms=0.0,
            success=False,
            effectiveness_score=0.0,
            timestamp=datetime.now(),
            performance_metrics={},
            ml_insights={},
            recommendations=[],
        )

        assert report.attack_name == "test_attack"
        assert report.success is False


class TestSystemPerformanceReport:
    """Tests for SystemPerformanceReport model."""

    def test_create_system_report(self):
        """Test creating a system performance report."""
        report = SystemPerformanceReport(
            report_period="24 hours",
            total_attacks=100,
            successful_attacks=85,
            average_effectiveness=0.82,
            performance_trends={"hour_1": {"success_rate": 90}},
            top_performing_attacks=["attack1", "attack2"],
            problematic_targets=["target1.com"],
            system_health_score=88.5,
            recommendations=["Monitor performance"],
        )

        assert report.total_attacks == 100
        assert report.successful_attacks == 85
        assert report.system_health_score == 88.5
        assert len(report.top_performing_attacks) == 2

    def test_empty_system_report(self):
        """Test creating empty system report."""
        report = SystemPerformanceReport(
            report_period="0 hours",
            total_attacks=0,
            successful_attacks=0,
            average_effectiveness=0.0,
            performance_trends={},
            top_performing_attacks=[],
            problematic_targets=[],
            system_health_score=0.0,
            recommendations=[],
        )

        assert report.total_attacks == 0
        assert len(report.recommendations) == 0
